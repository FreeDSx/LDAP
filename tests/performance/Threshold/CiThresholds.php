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
        'json:pcntl',
        'json:swoole',
        'sqlite:pcntl',
        'sqlite:swoole',
        'mysql:pcntl',
        'mysql:swoole',
    ];

    public static function forProfile(string $key): ThresholdSet
    {
        return match ($key) {
            'memory:swoole' => new ThresholdSet(
                maxErrors: 0,
                minThroughput: 800.0,
                maxP99Ms: 100.0,
            ),
            'json:pcntl' => new ThresholdSet(
                maxErrors: 0,
                minThroughput: 100.0,
                maxP99Ms: 800.0,
            ),
            'json:swoole' => new ThresholdSet(
                maxErrors: 0,
                minThroughput: 600.0,
                maxP99Ms: 150.0,
            ),
            'sqlite:pcntl' => new ThresholdSet(
                maxErrors: 0,
                minThroughput: 1100.0,
                maxP99Ms: 150.0,
            ),
            'sqlite:swoole' => new ThresholdSet(
                maxErrors: 0,
                minThroughput: 1000.0,
                maxP99Ms: 800.0,
            ),
            'mysql:pcntl' => new ThresholdSet(
                maxErrors: 0,
                minThroughput: 850.0,
                maxP99Ms: 200.0,
            ),
            'mysql:swoole' => new ThresholdSet(
                maxErrors: 0,
                minThroughput: 850.0,
                maxP99Ms: 200.0,
            ),
            default => throw new InvalidArgumentException(sprintf(
                'Unknown CI profile "%s". Known: %s.',
                $key,
                implode(', ', self::KNOWN_PROFILES),
            )),
        };
    }
}
