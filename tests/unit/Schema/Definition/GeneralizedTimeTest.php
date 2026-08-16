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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Definition;

use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class GeneralizedTimeTest extends TestCase
{
    public function test_parses_canonical_utc_form(): void
    {
        $parsed = GeneralizedTime::parse('20250415103000Z');

        self::assertEquals(
            new DateTimeImmutable(
                '2025-04-15T10:30:00Z',
                new DateTimeZone('UTC'),
            ),
            $parsed,
        );
        self::assertSame(
            'UTC',
            $parsed->getTimezone()->getName(),
        );
    }

    /**
     * RFC 4517 3.3.13 admits "60" as a leap second, and it names the instant after 59.
     */
    public function test_parses_a_leap_second_as_the_instant_it_names(): void
    {
        self::assertSame(
            '2017-01-01T00:00:00+00:00',
            GeneralizedTime::parse('20161231235960Z')->format('c'),
        );
    }

    public function test_parses_hour_only_precision(): void
    {
        $parsed = GeneralizedTime::parse('2025041510Z');

        self::assertSame(
            '2025-04-15T10:00:00+00:00',
            $parsed->format('c'),
        );
    }

    public function test_parses_hour_and_minute_precision(): void
    {
        $parsed = GeneralizedTime::parse('202504151030Z');

        self::assertSame(
            '2025-04-15T10:30:00+00:00',
            $parsed->format('c'),
        );
    }

    public function test_parses_fractional_seconds_with_dot(): void
    {
        $parsed = GeneralizedTime::parse('20250415103000.500Z');

        self::assertSame(
            '500000',
            $parsed->format('u'),
        );
    }

    public function test_parses_fractional_seconds_with_comma(): void
    {
        $parsed = GeneralizedTime::parse('20250415103000,250Z');

        self::assertSame(
            '250000',
            $parsed->format('u'),
        );
    }

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function zoneFormProvider(): array
    {
        return [
            'Z UTC' => ['20250415100000Z', '2025-04-15T10:00:00+00:00'],
            'plus hours only' => ['20250415100000+05', '2025-04-15T05:00:00+00:00'],
            'plus hours+minutes' => ['20250415100000+0530', '2025-04-15T04:30:00+00:00'],
            'minus hours only' => ['20250415100000-08', '2025-04-15T18:00:00+00:00'],
            'minus hours+minutes' => ['20250415100000-0800', '2025-04-15T18:00:00+00:00'],
        ];
    }

    #[DataProvider('zoneFormProvider')]
    public function test_parses_all_rfc4517_zone_forms_and_normalizes_to_utc(
        string $input,
        string $expectedUtcIso,
    ): void {
        $parsed = GeneralizedTime::parse($input);

        self::assertSame(
            $expectedUtcIso,
            $parsed->format('c'),
        );
    }

    public function test_parse_normalizes_to_utc(): void
    {
        $parsed = GeneralizedTime::parse('20250415100000-0500');

        self::assertSame(
            'UTC',
            $parsed->getTimezone()->getName(),
        );
        self::assertSame(
            '2025-04-15T15:00:00+00:00',
            $parsed->format('c'),
        );
    }

    public function test_format_emits_canonical_utc_form(): void
    {
        $instant = new DateTimeImmutable(
            '2025-04-15T10:30:00+05:00',
            new DateTimeZone('+05:00'),
        );

        self::assertSame(
            '20250415053000Z',
            GeneralizedTime::format($instant),
        );
    }

    public function test_round_trip_canonical(): void
    {
        $original = '20250415103000Z';

        self::assertSame(
            $original,
            GeneralizedTime::format(GeneralizedTime::parse($original)),
        );
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function invalidInputProvider(): array
    {
        return [
            'empty string' => [''],
            'missing zone' => ['20250415103000'],
            'too short for hour' => ['202504'],
            'invalid month 13' => ['20251315103000Z'],
            'invalid day Feb 30' => ['20250230103000Z'],
            'invalid hour 25' => ['20250415253000Z'],
            'extra characters' => ['20250415103000Zfoo'],
            'lowercase zone z' => ['20250415103000z'],
            'colon in zone' => ['20250415103000+05:00'],
            'date separators' => ['2025-04-15T10:30:00Z'],
            'non-digit garbage' => ['not-a-time'],
        ];
    }

    #[DataProvider('invalidInputProvider')]
    public function test_rejects_invalid_input(string $value): void
    {
        $this->expectException(InvalidArgumentException::class);

        GeneralizedTime::parse($value);
    }
}
