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

use Swoole\Coroutine;

use function max;

/**
 * Yields the current coroutine for a swoole safe sleeper.
 */
final class CoroutineSleeper implements SleeperInterface
{
    /**
     * Swoole sleep must not be less than this (otherwise it does not sleep at all).
     */
    private const MIN_SECONDS = 0.001;

    public function sleep(float $seconds): void
    {
        if ($seconds <= 0.0) {
            return;
        }

        Coroutine::sleep(max($seconds, self::MIN_SECONDS));
    }
}
