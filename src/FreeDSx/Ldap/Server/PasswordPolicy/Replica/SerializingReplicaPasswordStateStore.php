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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriterQueueInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

/**
 * Serializes replica password-state writes through the storage's single writer coroutine while reading per-coroutine.
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
        return $this->reads->load($dn);
    }

    /**
     * @param callable(ReplicaPasswordState): OperationalChanges $merge
     */
    public function atomicMutate(
        Dn $dn,
        callable $merge,
    ): void {
        $writes = $this->writes;
        $this->queue->run(static function () use ($writes, $dn, $merge): void {
            $writes->atomicMutate(
                $dn,
                $merge,
            );
        });
    }

    public function listUnforwarded(int $limit = 100): array
    {
        return $this->reads->listUnforwarded($limit);
    }

    public function markForwarded(
        Dn $dn,
        int $sequence,
    ): void {
        $writes = $this->writes;
        $this->queue->run(static function () use ($writes, $dn, $sequence): void {
            $writes->markForwarded(
                $dn,
                $sequence,
            );
        });
    }

    public function discardIfSuperseded(
        Dn $dn,
        UserPasswordState $authoritative,
    ): void {
        $writes = $this->writes;
        $this->queue->run(static function () use ($writes, $dn, $authoritative): void {
            $writes->discardIfSuperseded(
                $dn,
                $authoritative,
            );
        });
    }

    public function discard(Dn $dn): void
    {
        $writes = $this->writes;
        $this->queue->run(static function () use ($writes, $dn): void {
            $writes->discard($dn);
        });
    }
}
