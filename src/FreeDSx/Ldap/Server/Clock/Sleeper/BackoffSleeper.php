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

namespace FreeDSx\Ldap\Server\Clock\Sleeper;

use FreeDSx\Ldap\Server\Config\ReconnectBackoff;

/**
 * A stateful reconnect backoff: it sleeps the current delay and widens it, resetting to the initial after a success.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class BackoffSleeper
{
    private float $delay;

    public function __construct(
        private readonly ReconnectBackoff $backoff,
        private readonly SleeperInterface $sleeper,
    ) {
        $this->delay = $backoff->initial();
    }

    /**
     * Reset to the initial delay after a successful iteration.
     */
    public function reset(): void
    {
        $this->delay = $this->backoff->initial();
    }

    /**
     * Sleep the current delay, then widen it toward the ceiling for the next failure.
     */
    public function wait(): void
    {
        $this->sleeper->sleep($this->delay);
        $this->delay = $this->backoff->next($this->delay);
    }

    /**
     * The delay the next {@see wait()} will sleep.
     */
    public function delay(): float
    {
        return $this->delay;
    }
}
