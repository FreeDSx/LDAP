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

namespace FreeDSx\Ldap\Server\Config;

use function min;

/**
 * A bounded exponential backoff for reconnect attempts.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ReconnectBackoff
{
    public function __construct(
        private float $baseSeconds = 1.0,
        private float $maxSeconds = 30.0,
    ) {}

    /**
     * The delay to start from (and reset to after a successful connection).
     */
    public function initial(): float
    {
        return $this->baseSeconds;
    }

    /**
     * The next delay after the current one, doubling up to the ceiling.
     */
    public function next(float $current): float
    {
        return min(
            $current * 2.0,
            $this->maxSeconds,
        );
    }
}
