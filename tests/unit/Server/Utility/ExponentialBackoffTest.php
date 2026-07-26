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

namespace Tests\Unit\FreeDSx\Ldap\Server\Utility;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Utility\ExponentialBackoff;
use PHPUnit\Framework\TestCase;

final class ExponentialBackoffTest extends TestCase
{
    private ExponentialBackoff $subject;

    protected function setUp(): void
    {
        $this->subject = new ExponentialBackoff(
            base: 0.001,
            max: 0.05,
            jitter: 0.0,
        );
    }

    public function test_it_doubles_the_delay_for_each_attempt(): void
    {
        self::assertSame(
            0.001,
            $this->subject->delayFor(1),
        );
        self::assertSame(
            0.002,
            $this->subject->delayFor(2),
        );
        self::assertSame(
            0.004,
            $this->subject->delayFor(3),
        );
    }

    public function test_it_caps_the_delay_at_the_ceiling(): void
    {
        self::assertSame(
            0.05,
            $this->subject->delayFor(20),
        );
    }

    public function test_it_spreads_jittered_delays_across_the_window(): void
    {
        $subject = new ExponentialBackoff(
            base: 1.0,
            max: 10.0,
            jitter: 0.5,
        );

        $delays = [];
        for ($i = 0; $i < 200; $i++) {
            $delays[] = $subject->delayFor(1);
        }

        self::assertGreaterThanOrEqual(
            0.5,
            min($delays),
        );
        self::assertLessThanOrEqual(
            1.5,
            max($delays),
        );
        self::assertGreaterThan(
            1,
            count(array_unique($delays)),
        );
    }

    public function test_it_returns_an_exact_delay_when_jitter_is_disabled(): void
    {
        $delays = [];
        for ($i = 0; $i < 20; $i++) {
            $delays[] = $this->subject->delayFor(2);
        }

        self::assertSame(
            [0.002],
            array_values(array_unique($delays)),
        );
    }

    public function test_it_rejects_an_attempt_below_one(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->subject->delayFor(0);
    }

    public function test_it_rejects_a_base_delay_of_zero(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new ExponentialBackoff(
            base: 0.0,
            max: 1.0,
        );
    }

    public function test_it_rejects_a_ceiling_below_the_base_delay(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new ExponentialBackoff(
            base: 2.0,
            max: 1.0,
        );
    }

    public function test_it_rejects_jitter_outside_the_unit_range(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new ExponentialBackoff(
            base: 1.0,
            max: 2.0,
            jitter: 1.5,
        );
    }
}
