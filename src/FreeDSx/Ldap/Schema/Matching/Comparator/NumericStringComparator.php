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
 * Numeric string comparator treating spaces as insignificant (RFC 4517 section 4.2.22).
 */
final class NumericStringComparator implements MatchingRuleComparatorInterface, IndexableComparatorInterface
{
    use NormalizedIndexFormsTrait;

    public function __construct(
        private readonly StringPrep $prep = new StringPrep(),
    ) {}

    public function equals(
        string $a,
        string $b,
    ): bool {
        return $this->normalize($a) === $this->normalize($b);
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        return strcmp(
            $this->normalize($a),
            $this->normalize($b),
        );
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        $normalizedAssertion = new SubstringAssertion(
            initial: $assertion->initial !== null ? $this->normalize($assertion->initial) : null,
            any: array_map($this->normalize(...), $assertion->any),
            final: $assertion->final !== null ? $this->normalize($assertion->final) : null,
        );

        return (new CaseExactComparator())->substringMatches(
            $this->normalize($value),
            $normalizedAssertion,
        );
    }

    /**
     * RFC 4518 2.6.2: every space is insignificant, so the profile's space handling is simply undone here.
     */
    private function normalize(string $value): string
    {
        return str_replace(
            ' ',
            '',
            $this->prep->prepareForEquality($value),
        );
    }
}
