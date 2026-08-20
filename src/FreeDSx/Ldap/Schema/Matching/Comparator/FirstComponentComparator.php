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
 * Compares only the leading component of a parenthesised definition (RFC 4517 sections 4.2.15 and 4.2.26).
 */
final readonly class FirstComponentComparator implements MatchingRuleComparatorInterface, IndexableComparatorInterface
{
    public function __construct(private MatchingRuleComparatorInterface $component) {}

    public function equals(
        string $a,
        string $b,
    ): bool {
        return $this->component->equals(
            $this->firstComponent($a),
            $this->firstComponent($b),
        );
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        return $this->component->compare(
            $this->firstComponent($a),
            $this->firstComponent($b),
        );
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        return $this->component->substringMatches(
            $this->firstComponent($value),
            $assertion,
        );
    }

    public function indexKey(string $value): ?string
    {
        return $this->component instanceof IndexableComparatorInterface
            ? $this->component->indexKey($this->firstComponent($value))
            : null;
    }

    public function indexFragment(string $fragment): ?string
    {
        return $this->component instanceof IndexableComparatorInterface
            ? $this->component->indexFragment($fragment)
            : null;
    }

    /**
     * A value without parentheses is returned whole, so a bare assertion still compares against a full definition.
     */
    private function firstComponent(string $value): string
    {
        $trimmed = trim($value);

        if (!str_starts_with($trimmed, '(')) {
            return $trimmed;
        }

        $component = strtok(
            ltrim(substr($trimmed, 1)),
            " \t\r\n)",
        );

        return $component === false
            ? ''
            : $component;
    }
}
