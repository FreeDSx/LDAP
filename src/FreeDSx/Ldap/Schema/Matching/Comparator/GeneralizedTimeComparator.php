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

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Matching\IndexableComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;

/**
 * Generalized time comparator (generalizedTimeMatch / generalizedTimeOrderingMatch).
 */
final class GeneralizedTimeComparator implements MatchingRuleComparatorInterface, IndexableComparatorInterface
{
    /**
     * A fixed-width UTC spelling that still orders lexically.
     */
    private const CANONICAL_FORMAT = 'YmdHis.u\Z';

    public function equals(
        string $a,
        string $b,
    ): bool {
        $canonicalA = $this->canonical($a);
        $canonicalB = $this->canonical($b);

        if ($canonicalA === null || $canonicalB === null) {
            return false;
        }

        return $canonicalA === $canonicalB;
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        $canonicalA = $this->canonical($a);
        $canonicalB = $this->canonical($b);

        if ($canonicalA === null || $canonicalB === null) {
            return ($canonicalA === null ? 1 : 0) <=> ($canonicalB === null ? 1 : 0);
        }

        return $canonicalA <=> $canonicalB;
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        return false;
    }

    public function indexKey(string $value): ?string
    {
        return $this->canonical($value);
    }

    public function indexFragment(string $fragment): ?string
    {
        return null;
    }

    private function canonical(string $value): ?string
    {
        try {
            return GeneralizedTime::parse($value)
                ->format(self::CANONICAL_FORMAT);
        } catch (InvalidArgumentException) {
            return null;
        }
    }
}
