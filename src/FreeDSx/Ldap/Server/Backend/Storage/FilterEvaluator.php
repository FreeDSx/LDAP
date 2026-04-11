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

namespace FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\ApproximateFilter;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\LessThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Search\Filter\OrFilter;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;

/**
 * Pure-PHP implementation of FilterEvaluatorInterface.
 *
 * Evaluates LDAP filters against in-memory Entry objects. Attribute name
 * comparisons are always case-insensitive. Value comparisons default to
 * case-insensitive string comparison, matching the caseIgnoreMatch semantics
 * used by the majority of LDAP schema attribute types.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class FilterEvaluator implements FilterEvaluatorInterface
{
    private const MATCHING_RULE_CASE_IGNORE = '2.5.13.2';

    private const MATCHING_RULE_CASE_EXACT = '2.5.13.5';

    private const MATCHING_RULE_BIT_AND = '1.2.840.113556.1.4.803';

    private const MATCHING_RULE_BIT_OR = '1.2.840.113556.1.4.804';

    public function evaluate(
        Entry $entry,
        FilterInterface $filter,
    ): bool {
        return match (true) {
            $filter instanceof AndFilter => $this->evaluateAnd($entry, $filter),
            $filter instanceof OrFilter => $this->evaluateOr($entry, $filter),
            $filter instanceof NotFilter => $this->evaluateNot($entry, $filter),
            $filter instanceof PresentFilter => $this->evaluatePresent($entry, $filter),
            $filter instanceof EqualityFilter => $this->evaluateEquality($entry, $filter),
            $filter instanceof SubstringFilter => $this->evaluateSubstring($entry, $filter),
            $filter instanceof GreaterThanOrEqualFilter => $this->evaluateGreaterOrEqual($entry, $filter),
            $filter instanceof LessThanOrEqualFilter => $this->evaluateLessOrEqual($entry, $filter),
            $filter instanceof ApproximateFilter => $this->evaluateApproximate($entry, $filter),
            $filter instanceof MatchingRuleFilter => $this->evaluateMatchingRule($entry, $filter),
            default => throw new OperationException(
                sprintf('Unrecognized filter type: %s', get_class($filter)),
                ResultCode::PROTOCOL_ERROR,
            ),
        };
    }

    private function evaluateAnd(
        Entry $entry,
        AndFilter $filter,
    ): bool {
        foreach ($filter->get() as $child) {
            if (!$this->evaluate($entry, $child)) {
                return false;
            }
        }

        return true;
    }

    private function evaluateOr(
        Entry $entry,
        OrFilter $filter,
    ): bool {
        foreach ($filter->get() as $child) {
            if ($this->evaluate($entry, $child)) {
                return true;
            }
        }

        return false;
    }

    private function evaluateNot(
        Entry $entry,
        NotFilter $filter,
    ): bool {
        return !$this->evaluate($entry, $filter->get());
    }

    private function evaluatePresent(
        Entry $entry,
        PresentFilter $filter,
    ): bool {
        return $entry->has($filter->getAttribute());
    }

    private function evaluateEquality(
        Entry $entry,
        EqualityFilter $filter,
    ): bool {
        $attribute = $entry->get($filter->getAttribute());

        if ($attribute === null) {
            return false;
        }

        $filterValue = strtolower($filter->getValue());

        foreach ($attribute->getValues() as $value) {
            if (strtolower($value) === $filterValue) {
                return true;
            }
        }

        return false;
    }

    private function evaluateSubstring(
        Entry $entry,
        SubstringFilter $filter,
    ): bool {
        $attribute = $entry->get($filter->getAttribute());

        if ($attribute === null) {
            return false;
        }

        $startsWith = $filter->getStartsWith() !== null
            ? strtolower($filter->getStartsWith())
            : null;
        $endsWith = $filter->getEndsWith() !== null
            ? strtolower($filter->getEndsWith())
            : null;
        $contains = array_map('strtolower', $filter->getContains());

        foreach ($attribute->getValues() as $value) {
            if ($this->substringMatches(strtolower($value), $startsWith, $endsWith, $contains)) {
                return true;
            }
        }

        return false;
    }

    /**
     * RFC 4511 §4.5.1.7.1 — evaluate one attribute value against the decomposed substring components.
     *
     * Each matched portion must start strictly after the end of the previous one:
     *   initial occupies [0, len(initial)-1], so 'any' searches start at len(initial).
     *   After all 'any' matches, 'final' must begin at a position >= $pos.
     *
     * @param string[] $contains
     */
    private function substringMatches(
        string $value,
        ?string $startsWith,
        ?string $endsWith,
        array $contains,
    ): bool {
        if ($startsWith !== null && !str_starts_with($value, $startsWith)) {
            return false;
        }

        // Start 'any' searches after the initial match, not at position 0.
        $pos = $startsWith !== null ? strlen($startsWith) : 0;

        foreach ($contains as $substr) {
            $found = strpos($value, $substr, $pos);
            if ($found === false) {
                return false;
            }
            $pos = $found + strlen($substr);
        }

        if ($endsWith === null) {
            return true;
        }

        // 'final' must be at the end of the value AND must not overlap the previous match.
        $endsWithStart = strlen($value) - strlen($endsWith);

        return $endsWithStart >= $pos && str_ends_with($value, $endsWith);
    }

    private function evaluateGreaterOrEqual(
        Entry $entry,
        GreaterThanOrEqualFilter $filter,
    ): bool {
        $attribute = $entry->get($filter->getAttribute());

        if ($attribute === null) {
            return false;
        }

        $filterValue = $filter->getValue();

        foreach ($attribute->getValues() as $value) {
            if ($this->compareOrdered($value, $filterValue) >= 0) {
                return true;
            }
        }

        return false;
    }

    private function evaluateLessOrEqual(
        Entry $entry,
        LessThanOrEqualFilter $filter,
    ): bool {
        $attribute = $entry->get($filter->getAttribute());

        if ($attribute === null) {
            return false;
        }

        $filterValue = $filter->getValue();

        foreach ($attribute->getValues() as $value) {
            if ($this->compareOrdered($value, $filterValue) <= 0) {
                return true;
            }
        }

        return false;
    }

    private function compareOrdered(
        string $value,
        string $filterValue,
    ): int {
        if (ctype_digit($value) && ctype_digit($filterValue)) {
            return (int) $value <=> (int) $filterValue;
        }

        return strcasecmp($value, $filterValue);
    }

    private function evaluateApproximate(
        Entry $entry,
        ApproximateFilter $filter,
    ): bool {
        // The LDAP spec does not define approximate matching precisely.
        // Most servers treat it as case-insensitive equality, which we mirror here.
        $attribute = $entry->get($filter->getAttribute());

        if ($attribute === null) {
            return false;
        }

        $filterValue = strtolower($filter->getValue());

        foreach ($attribute->getValues() as $value) {
            if (strtolower($value) === $filterValue) {
                return true;
            }
        }

        return false;
    }

    private function evaluateMatchingRule(
        Entry $entry,
        MatchingRuleFilter $filter,
    ): bool {
        $filterValue = $filter->getValue();

        foreach ($this->collectValuesToTest($entry, $filter) as $value) {
            if ($this->matchByRule($filter->getMatchingRule(), $value, $filterValue)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<string>
     */
    private function collectValuesToTest(
        Entry $entry,
        MatchingRuleFilter $filter,
    ): array {
        $filterAttributeName = $filter->getAttribute();
        $values = [];

        if ($filterAttributeName !== null) {
            $attribute = $entry->get($filterAttributeName);
            if ($attribute !== null) {
                $values = $attribute->getValues();
            }
        } else {
            // Null attribute name: match against all attributes
            foreach ($entry->getAttributes() as $attribute) {
                foreach ($attribute->getValues() as $v) {
                    $values[] = $v;
                }
            }
        }

        // Optionally also match against RDN component values from the entry's DN
        if ($filter->getUseDnAttributes()) {
            foreach ($entry->getDn()->toArray() as $rdn) {
                $values[] = $rdn->getValue();
            }
        }

        return $values;
    }

    private function matchByRule(
        ?string $rule,
        string $value,
        string $filterValue,
    ): bool {
        return match ($rule) {
            null, self::MATCHING_RULE_CASE_IGNORE => strtolower($value) === strtolower($filterValue),
            self::MATCHING_RULE_CASE_EXACT => $value === $filterValue,
            self::MATCHING_RULE_BIT_AND => ((int) $value & (int) $filterValue) === (int) $filterValue,
            self::MATCHING_RULE_BIT_OR => ((int) $value & (int) $filterValue) !== 0,
            default => throw new OperationException(
                sprintf('Unsupported matching rule: %s', $rule),
                ResultCode::INAPPROPRIATE_MATCHING,
            ),
        };
    }
}
