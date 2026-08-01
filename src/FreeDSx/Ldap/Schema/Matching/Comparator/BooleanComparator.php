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
 * Boolean comparator (booleanMatch): compares RFC 4517 boolean literals TRUE/FALSE case-insensitively.
 */
final class BooleanComparator implements MatchingRuleComparatorInterface
{
    public function equals(
        string $a,
        string $b,
    ): bool {
        return strtoupper($a) === strtoupper($b);
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        return strcmp(strtoupper($a), strtoupper($b));
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        return false;
    }
}
