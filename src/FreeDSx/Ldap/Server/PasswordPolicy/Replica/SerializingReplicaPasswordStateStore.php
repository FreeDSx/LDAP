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
 * Serializes replica password-state writes through the storage's single writer coroutine while reading per-coroutine.
 *
 * Callers already running on that writer bypass both, since its transaction is open on the write store.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SerializingReplicaPasswordStateStore implements ReplicaPasswordStateStoreInterface
{
    public function __construct(
        private ReplicaPasswordStateStoreInterface $reads,
        private ReplicaPasswordStateStoreInterface $writes,
        private WriterQueueInterface $queue,
    ) {}

    public function load(Dn $dn): ReplicaPasswordState
    {
        return $this->readStore()->load($dn);
    }

    /**
     * @param callable(ReplicaPasswordState): OperationalChanges $merge
     */
    public function atomicMutate(
        Dn $dn,
        callable $merge,
    ): void {
        $this->submit(fn() => $this->writes->atomicMutate(
            $dn,
            $merge,
        ));
    }

    public function listUnforwarded(int $limit = 100): array
    {
        return $this->readStore()->listUnforwarded($limit);
    }

    public function markForwarded(
        Dn $dn,
        int $sequence,
    ): void {
        $this->submit(fn() => $this->writes->markForwarded(
            $dn,
            $sequence,
        ));
    }

    public function discardIfSuperseded(
        Dn $dn,
        UserPasswordState $authoritative,
    ): void {
        $this->submit(fn() => $this->writes->discardIfSuperseded(
            $dn,
            $authoritative,
        ));
    }

    public function discard(Dn $dn): void
    {
        $this->submit(fn() => $this->writes->discard($dn));
    }

    /**
     * The write store while the writer is executing, since the read store cannot see its uncommitted changes.
     */
    private function readStore(): ReplicaPasswordStateStoreInterface
    {
        return $this->queue->isWriter()
            ? $this->writes
            : $this->reads;
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
