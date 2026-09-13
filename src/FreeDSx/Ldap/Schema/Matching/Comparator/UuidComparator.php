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

use FreeDSx\Ldap\Schema\Matching\IndexableComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;

use function strcmp;
use function strtolower;

/**
 * UUID comparator (uuidMatch / uuidOrderingMatch): compares the RFC 4122 string form with case-insensitive hex digits.
 */
final class UuidComparator implements MatchingRuleComparatorInterface, IndexableComparatorInterface
{
    public function equals(
        string $a,
        string $b,
    ): bool {
        return strtolower($a) === strtolower($b);
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        return strcmp(
            strtolower($a),
            strtolower($b),
        );
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        return false;
    }

    public function indexKey(string $value): string
    {
        return strtolower($value);
    }

    public function indexFragment(string $fragment): ?string
    {
        return null;
    }
}
