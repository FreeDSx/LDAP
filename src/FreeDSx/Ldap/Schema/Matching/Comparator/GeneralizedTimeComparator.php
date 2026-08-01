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

namespace FreeDSx\Ldap\Schema\Matching\Comparator;

use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;

/**
 * Generalized time comparator (generalizedTimeMatch / generalizedTimeOrderingMatch).
 * Timestamps are parsed and compared as UTC Unix timestamps.
 */
final class GeneralizedTimeComparator implements MatchingRuleComparatorInterface
{
    /**
     * RFC 4517 §3.3.13 allows three forms:
     * - Z suffix (UTC): 20060102150405Z
     * - Numeric offset: 20060102150405+0500
     * - No suffix (treated as UTC per LDAP convention): 20060102150405
     */
    private const FORMATS = [
        'YmdHis\Z',
        'YmdHisO',
        'YmdHis',
    ];

    private static DateTimeZone $utc;

    public function equals(
        string $a,
        string $b,
    ): bool {
        $tsA = $this->toTimestamp($a);
        $tsB = $this->toTimestamp($b);

        if ($tsA === null || $tsB === null) {
            return false;
        }

        return $tsA === $tsB;
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        return ($this->toTimestamp($a) ?? 0) <=> ($this->toTimestamp($b) ?? 0);
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        return false;
    }

    private function toTimestamp(string $value): ?int
    {
        self::$utc ??= new DateTimeZone('UTC');

        foreach (self::FORMATS as $format) {
            $dt = DateTimeImmutable::createFromFormat($format, $value, self::$utc);
            if ($dt !== false) {
                return $dt->getTimestamp();
            }
        }

        return null;
    }
}
