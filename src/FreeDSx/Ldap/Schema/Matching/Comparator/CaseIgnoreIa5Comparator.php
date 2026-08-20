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

/**
 * Case-insensitive IA5 (ASCII) string comparator (caseIgnoreIA5Match / caseIgnoreIA5SubstringsMatch).
 * Behaviorally identical to CaseIgnoreComparator since IA5 is a subset of ASCII.
 */
final readonly class CaseIgnoreIa5Comparator implements MatchingRuleComparatorInterface, IndexableComparatorInterface
{
    private CaseIgnoreComparator $inner;

    public function __construct()
    {
        $this->inner = new CaseIgnoreComparator();
    }

    public function equals(
        string $a,
        string $b,
    ): bool {
        return $this->inner->equals($a, $b);
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        return $this->inner->compare($a, $b);
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        return $this->inner->substringMatches(
            $value,
            $assertion,
        );
    }

    public function indexKey(string $value): string
    {
        return $this->inner->indexKey($value);
    }

    public function indexFragment(string $fragment): string
    {
        return $this->inner->indexFragment($fragment);
    }
}
