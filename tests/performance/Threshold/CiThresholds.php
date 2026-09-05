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

namespace Tests\Performance\FreeDSx\Ldap\Threshold;

use InvalidArgumentException;

/**
 * Built-in CI threshold defaults for each (backend, runner) profile.
 */
final class CiThresholds
{
    /**
     * @var list<string>
     */
    public const KNOWN_PROFILES = [
        'memory:swoole',
        'sqlite:pcntl',
        'sqlite:swoole',
        'sqlite:swoole-pool',
        'mysql:pcntl',
        'mysql:swoole',
    ];

    /**
     * A failed operation is a defect on every profile.
     */
    private const MAX_ERRORS = 0;

    /**
     * Set low enough that only a collapse trips it.
     */
    private const MIN_THROUGHPUT = 250.0;

    /**
     * Set high enough that only a collapse trips it.
     */
    private const MAX_P99_MS = 3_000.0;

    public static function forProfile(string $key): ThresholdSet
    {
        if (!in_array($key, self::KNOWN_PROFILES, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unknown CI profile "%s". Known: %s.',
                $key,
                implode(', ', self::KNOWN_PROFILES),
            ));
        }

        // Latency and throughput vary far more with the runner than with a regression, so the error count is the guard.
        return new ThresholdSet(
            maxErrors: self::MAX_ERRORS,
            minThroughput: self::MIN_THROUGHPUT,
            maxP99Ms: self::MAX_P99_MS,
        );
    }
}
