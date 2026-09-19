<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server\PasswordPolicy\Replica;

use Closure;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriterQueueInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

/**
 * Serializes replica password-state writes through the storage's single writer coroutine; reads run in place.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SerializingReplicaPasswordStateStore implements ReplicaPasswordStateStoreInterface
{
    public function __construct(
        private ReplicaPasswordStateStoreInterface $store,
        private WriterQueueInterface $queue,
    ) {}

    public function load(Dn $dn): ReplicaPasswordState
    {
        return $this->store->load($dn);
    }

    /**
     * @param callable(ReplicaPasswordState): OperationalChanges $merge
     */
    public function atomicMutate(
        Dn $dn,
        callable $merge,
    ): void {
        $this->submit(fn() => $this->store->atomicMutate(
            $dn,
            $merge,
        ));
    }

    public function listUnforwarded(int $limit = 100): array
    {
        return $this->store->listUnforwarded($limit);
    }

    public function markForwarded(
        Dn $dn,
        int $sequence,
    ): void {
        $this->submit(fn() => $this->store->markForwarded(
            $dn,
            $sequence,
        ));
    }

    public function discardIfSuperseded(
        Dn $dn,
        UserPasswordState $authoritative,
    ): void {
        $this->submit(fn() => $this->store->discardIfSuperseded(
            $dn,
            $authoritative,
        ));
    }

    public function discard(Dn $dn): void
    {
        $this->submit(fn() => $this->store->discard($dn));
    }

    /**
     * Runs directly when the writer is already executing, since submitting there would block the writer on itself.
     *
     * @param Closure(): void $write
     */
    private function submit(Closure $write): void
    {
        if ($this->queue->isWriter()) {
            $write();

            return;
        }

        $this->queue->run($write);
    }
}
