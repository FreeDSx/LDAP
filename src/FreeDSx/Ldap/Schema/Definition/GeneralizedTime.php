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

namespace FreeDSx\Ldap\Schema\Definition;

use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Ldap\Exception\InvalidArgumentException;

/**
 * Parser and formatter for the GeneralizedTime LDAP syntax (RFC 4517 §3.3.13).
 *
 * Format always emits the canonical "YYYYMMDDHHMMSSZ" UTC form.
 */
final class GeneralizedTime
{
    /**
     * The RFC 4517 3.3.13 ranges, since the offset never reaches the calendar check below.
     */
    private const PATTERN = '/^
        (?<year>\d{4})
        (?<month>0[1-9]|1[0-2])
        (?<day>0[1-9]|[12]\d|3[01])
        (?<hour>[01]\d|2[0-3])
        (?:(?<minute>[0-5]\d)
            (?:(?<second>[0-5]\d|60))?
        )?
        (?:[.,](?<fraction>\d+))?
        (?<zone>Z|[+\-](?:[01]\d|2[0-3])(?:[0-5]\d)?)
    $/xD';

    /**
     * RFC 4517 3.3.13 admits "60" as a leap second, which no calendar holds.
     */
    private const LEAP_SECOND = '60';

    private function __construct() {}

    /**
     * @throws InvalidArgumentException when the value is not a valid GeneralizedTime.
     */
    public static function parse(string $value): DateTimeImmutable
    {
        if (preg_match(self::PATTERN, $value, $matches) !== 1) {
            throw new InvalidArgumentException(sprintf(
                'Value "%s" is not a valid GeneralizedTime.',
                $value,
            ));
        }

        $iso = self::componentsToIso8601($matches);
        $parsed = DateTimeImmutable::createFromFormat(
            self::isoFormat($matches),
            $iso,
        );
        $errors = DateTimeImmutable::getLastErrors();
        $hasOverflow = $errors !== false
            && ($errors['warning_count'] > 0 || $errors['error_count'] > 0);
        if ($parsed === false || $hasOverflow) {
            throw new InvalidArgumentException(sprintf(
                'Value "%s" contains an invalid date or time component.',
                $value,
            ));
        }

        return self::applyLeapSecond($parsed, $matches)
            ->setTimezone(new DateTimeZone('UTC'));
    }

    /**
     * Render as the canonical UTC GeneralizedTime form: YYYYMMDDHHMMSSZ.
     */
    public static function format(DateTimeImmutable $instant): string
    {
        return $instant
            ->setTimezone(new DateTimeZone('UTC'))
            ->format('YmdHis') . 'Z';
    }

    /**
     * Render with a fractional-seconds field, for multi-valued attributes that must hold unique values such as
     * pwdFailureTime and pwdGraceUseTime; {@see format()} stays second-resolution for canonical single-valued stamps.
     */
    public static function formatWithFraction(DateTimeImmutable $instant): string
    {
        return $instant
            ->setTimezone(new DateTimeZone('UTC'))
            ->format('YmdHis.u') . 'Z';
    }

    /**
     * A leap second is parsed as second 59, so the instant it names is one second later.
     *
     * @param array<int|string, string> $components named capture groups
     */
    private static function applyLeapSecond(
        DateTimeImmutable $parsed,
        array $components,
    ): DateTimeImmutable {
        if (($components['second'] ?? '') !== self::LEAP_SECOND) {
            return $parsed;
        }

        return $parsed->modify('+1 second');
    }

    /**
     * @param array<int|string, string> $components named capture groups
     */
    private static function componentsToIso8601(array $components): string
    {
        $minute = ($components['minute'] ?? '') !== '' ? $components['minute'] : '00';
        $second = ($components['second'] ?? '') !== '' ? $components['second'] : '00';
        // No calendar holds :60, so it is parsed as :59 and stepped forward once the instant exists.
        $second = $second === self::LEAP_SECOND ? '59' : $second;
        $fraction = ($components['fraction'] ?? '') !== '' ? '.' . $components['fraction'] : '';
        $zone = $components['zone'] === 'Z'
            ? '+0000'
            : self::normalizeZone($components['zone']);

        return sprintf(
            '%s-%s-%sT%s:%s:%s%s%s',
            $components['year'],
            $components['month'],
            $components['day'],
            $components['hour'],
            $minute,
            $second,
            $fraction,
            $zone,
        );
    }

    /**
     * @param array<int|string, string> $components named capture groups
     */
    private static function isoFormat(array $components): string
    {
        $fraction = ($components['fraction'] ?? '') !== '' ? '.u' : '';

        return 'Y-m-d\\TH:i:s' . $fraction . 'O';
    }

    private static function normalizeZone(string $zone): string
    {
        return strlen($zone) === 3
            ? $zone . '00'
            : $zone;
    }
}
