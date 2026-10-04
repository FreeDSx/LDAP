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

namespace FreeDSx\Ldap\Server\ServerRunner\Swoole;

/**
 * Counts the connections a server holds against its connection limit.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ConnectionSlotsInterface
{
    /**
     * Takes a slot unless the limit is already reached; a limit of zero or less is no limit.
     */
    public function tryAcquire(int $maxConnections): bool;

    public function release(): void;

    /**
     * A respawned worker reuses its id, so claiming it frees the slots its predecessor still held.
     */
    public function claimWorker(int $workerId): void;
}
