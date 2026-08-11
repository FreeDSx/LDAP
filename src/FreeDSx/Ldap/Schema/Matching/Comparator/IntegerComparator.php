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

use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;

/**
 * Integer comparator (integerMatch / integerOrderingMatch): compares string representations as integers.
 */
final class IntegerComparator implements MatchingRuleComparatorInterface
{
    public function equals(
        string $a,
        string $b,
    ): bool {
        $left = self::canonical($a);
        $right = self::canonical($b);

        return $left !== null
            && $left === $right;
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        $left = self::canonical($a);
        $right = self::canonical($b);

        if ($left === null || $right === null) {
            return strcmp($a, $b);
        }

        return self::compareCanonical($left, $right);
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        return false;
    }

    /**
     * An integer reduced to one spelling, or null when the value is not one.
     *
     * Values can exceed the platform integer, so they stay as digits rather than being cast.
     */
    private static function canonical(string $value): ?string
    {
        if (preg_match('/^[+-]?\d+$/', $value) !== 1) {
            return null;
        }

        $isNegative = $value[0] === '-';
        $digits = ltrim(ltrim($value, '+-'), '0');

        if ($digits === '') {
            return '0';
        }

        return ($isNegative ? '-' : '') . $digits;
    }

    private static function compareCanonical(
        string $a,
        string $b,
    ): int {
        $aNegative = $a[0] === '-';
        $bNegative = $b[0] === '-';

        if ($aNegative !== $bNegative) {
            return $aNegative ? -1 : 1;
        }

        $magnitude = strlen($a) <=> strlen($b) ?: strcmp($a, $b);

        return $aNegative ? -$magnitude : $magnitude;
    }
}
