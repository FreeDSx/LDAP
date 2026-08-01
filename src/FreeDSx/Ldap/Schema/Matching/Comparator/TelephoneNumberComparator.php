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
 * Telephone number comparator (telephoneNumberMatch): strips spaces and hyphens before comparing case-insensitively.
 */
final class TelephoneNumberComparator implements MatchingRuleComparatorInterface
{
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
        $normalized = $this->normalize($value);
        $normalizedAssertion = new SubstringAssertion(
            initial: $assertion->initial !== null ? $this->normalize($assertion->initial) : null,
            any: array_map($this->normalize(...), $assertion->any),
            final: $assertion->final !== null ? $this->normalize($assertion->final) : null,
        );

        return (new CaseIgnoreComparator())->substringMatches(
            $normalized,
            $normalizedAssertion,
        );
    }

    private function normalize(string $value): string
    {
        return strtolower(str_replace(
            [' ', '-'],
            '',
            $value,
        ));
    }
}
