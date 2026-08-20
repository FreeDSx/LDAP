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
use FreeDSx\Ldap\Schema\Matching\StringPrep;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;

/**
 * String comparator that applies an RFC 4518 preparation profile, then matches byte-exact.
 */
final readonly class PreparedStringComparator implements MatchingRuleComparatorInterface, IndexableComparatorInterface
{
    private OctetStringComparator $matcher;

    public function __construct(
        private StringPrep $prep,
    ) {
        $this->matcher = new OctetStringComparator();
    }

    public function equals(
        string $a,
        string $b,
    ): bool {
        return $this->prep->prepareForEquality($a)
            === $this->prep->prepareForEquality($b);
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        return strcmp(
            $this->prep->prepareForEquality($a),
            $this->prep->prepareForEquality($b),
        );
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        return $this->matcher->substringMatches(
            $this->prep->prepareForEquality($value),
            $this->prepareAssertion($assertion),
        );
    }

    public function indexKey(string $value): string
    {
        return $this->prep->prepareForEquality($value);
    }

    public function indexFragment(string $fragment): string
    {
        return $this->prep->prepareFragment($fragment);
    }

    private function prepareAssertion(SubstringAssertion $assertion): SubstringAssertion
    {
        return new SubstringAssertion(
            initial: $assertion->initial !== null
                ? $this->prep->prepareFragment($assertion->initial)
                : null,
            any: array_map(
                $this->prep->prepareFragment(...),
                $assertion->any,
            ),
            final: $assertion->final !== null
                ? $this->prep->prepareFragment($assertion->final)
                : null,
        );
    }
}
