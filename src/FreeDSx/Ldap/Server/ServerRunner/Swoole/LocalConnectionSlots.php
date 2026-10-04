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
 * Connection slots for a server that runs in a single process.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LocalConnectionSlots implements ConnectionSlotsInterface
{
    private int $held = 0;

    public function tryAcquire(int $maxConnections): bool
    {
        if ($maxConnections > 0 && $this->held >= $maxConnections) {
            return false;
        }
        $this->held++;

        return true;
    }

    public function release(): void
    {
        $this->held--;
    }

    public function claimWorker(int $workerId): void
    {
        $this->held = 0;
    }
}
