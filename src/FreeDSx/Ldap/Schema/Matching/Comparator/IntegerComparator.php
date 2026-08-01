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
        return (int) $a === (int) $b;
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        return (int) $a <=> (int) $b;
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        return false;
    }
}
