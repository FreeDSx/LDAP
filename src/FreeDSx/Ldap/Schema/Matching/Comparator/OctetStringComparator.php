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
 * Exact byte-for-byte comparator (octetStringMatch): no case folding or normalization.
 */
final class OctetStringComparator implements MatchingRuleComparatorInterface
{
    public function equals(
        string $a,
        string $b,
    ): bool {
        return $a === $b;
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        return strcmp($a, $b);
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        if ($assertion->initial !== null && !str_starts_with($value, $assertion->initial)) {
            return false;
        }

        $pos = $assertion->initial !== null ? strlen($assertion->initial) : 0;

        foreach ($assertion->any as $substr) {
            $found = strpos($value, $substr, $pos);
            if ($found === false) {
                return false;
            }
            $pos = $found + strlen($substr);
        }

        if ($assertion->final === null) {
            return true;
        }

        $finalStart = strlen($value) - strlen($assertion->final);

        return $finalStart >= $pos
            && str_ends_with($value, $assertion->final);
    }
}
