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

namespace Tests\Unit\FreeDSx\Ldap\Server\Clock\Sleeper;

use FreeDSx\Ldap\Server\Clock\Sleeper\CoroutineSleeper;
use PHPUnit\Framework\TestCase;
use Swoole\Coroutine;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;

final class CoroutineSleeperTest extends TestCase
{
    use RequiresExtensionsTrait;

    protected function setUp(): void
    {
        $this->requireSwoole();
    }

    /**
     * A retry backoff can ask for less than swoole's timer accepts, where it would warn and not sleep at all.
     */
    public function test_a_sleep_below_the_swoole_minimum_still_sleeps(): void
    {
        self::assertGreaterThanOrEqual(
            0.9,
            $this->millisecondsSleeping(0.0005),
        );
    }

    public function test_a_sleep_above_the_swoole_minimum_is_left_alone(): void
    {
        self::assertGreaterThanOrEqual(
            4.0,
            $this->millisecondsSleeping(0.005),
        );
    }

    public function test_a_zero_sleep_does_not_yield(): void
    {
        self::assertLessThan(
            0.5,
            $this->millisecondsSleeping(0.0),
        );
    }

    private function millisecondsSleeping(float $seconds): float
    {
        $elapsed = 0.0;

        Coroutine\run(static function () use ($seconds, &$elapsed): void {
            $started = microtime(true);
            (new CoroutineSleeper())->sleep($seconds);
            $elapsed = (microtime(true) - $started) * 1000;
        });

        return $elapsed;
    }
}
