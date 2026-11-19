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

namespace FreeDSx\Ldap\Sync\Consumer\Checkpoint;

/**
 * Holds the sync cookie in memory only; a restart resumes with a full refresh.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class InMemoryReplicationCheckpoint implements ReplicationCheckpointInterface
{
    private ?string $cookie = null;

    public function read(): ?string
    {
        return $this->cookie;
    }

    public function write(string $cookie): void
    {
        $this->cookie = $cookie;
    }

    public function clear(): void
    {
        $this->cookie = null;
    }
}
