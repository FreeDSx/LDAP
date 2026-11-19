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
 * Persists the sync cookie so a replica can resume across restarts.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ReplicationCheckpointInterface
{
    /**
     * The cookie persisted by the last successful sync, or null when no checkpoint exists yet.
     */
    public function read(): ?string;

    /**
     * Persist the cookie as the resume point for the next sync.
     */
    public function write(string $cookie): void;

    /**
     * Remove the persisted cookie, leaving the next sync to start with a full refresh.
     */
    public function clear(): void;
}
