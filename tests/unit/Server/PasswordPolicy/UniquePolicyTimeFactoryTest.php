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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy;

use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Ldap\Server\PasswordPolicy\UniquePolicyTimeFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;
use Tests\Support\FreeDSx\Ldap\Clock\SequenceClock;

final class UniquePolicyTimeFactoryTest extends TestCase
{
    private const FORMAT = 'Y-m-d H:i:s.u';

    public function test_it_stamps_the_current_time_with_its_microseconds(): void
    {
        self::assertSame(
            '2026-05-20 12:00:00.123456',
            $this->factoryAt('2026-05-20T12:00:00.123456Z')->next([])->format(self::FORMAT),
        );
    }

    #[DataProvider('tickProvider')]
    public function test_it_reads_the_clock_once_when_it_ticks_over_a_boundary(
        string $before,
        string $after,
    ): void {
        $factory = new UniquePolicyTimeFactory(new SequenceClock(
            $before,
            $after,
            $after,
            $after,
        ));

        self::assertSame(
            self::utc($before)->format(self::FORMAT),
            $factory->next([])->format(self::FORMAT),
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function tickProvider(): iterable
    {
        yield 'a minute' => [
            '2026-11-23T10:34:59.999999Z',
            '2026-11-23T10:35:00.000001Z',
        ];
        yield 'an hour' => [
            '2026-11-23T10:59:59.999999Z',
            '2026-11-23T11:00:00.000001Z',
        ];
        yield 'midnight' => [
            '2026-11-23T23:59:59.999999Z',
            '2026-11-24T00:00:00.000001Z',
        ];
    }

    public function test_a_stamp_that_would_repeat_moves_past_the_newest(): void
    {
        self::assertSame(
            '2026-05-20 12:00:00.100001',
            $this->factoryAt('2026-05-20T12:00:00.100000Z')->next([
                self::utc('2026-05-20T12:00:00.050000Z'),
                self::utc('2026-05-20T12:00:00.100000Z'),
            ])->format(self::FORMAT),
        );
    }

    public function test_a_stamp_never_falls_before_an_existing_value(): void
    {
        self::assertSame(
            '2026-05-20 12:00:05.000001',
            $this->factoryAt('2026-05-20T12:00:00.100000Z')->next([
                self::utc('2026-05-20T12:00:05.000000Z'),
            ])->format(self::FORMAT),
        );
    }

    public function test_two_servers_stamping_in_one_second_at_different_microseconds_stamp_different_values(): void
    {
        self::assertNotSame(
            $this->factoryAt('2026-05-20T12:00:00.100000Z')->next([])->format(self::FORMAT),
            $this->factoryAt('2026-05-20T12:00:00.200000Z')->next([])->format(self::FORMAT),
        );
    }

    private function factoryAt(string $instant): UniquePolicyTimeFactory
    {
        return new UniquePolicyTimeFactory(FrozenClock::fromString($instant));
    }

    private static function utc(string $instant): DateTimeImmutable
    {
        return new DateTimeImmutable(
            $instant,
            new DateTimeZone('UTC'),
        );
    }
}
