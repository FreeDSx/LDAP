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
 * Evaluates LDAP filters against in-memory Entry objects using the three-valued logic (TRUE / FALSE / UNDEFINED)
 * required by RFC 4511 §4.5.1.
 *
 * Attribute name comparisons are always case-insensitive. Value comparisons default to case-insensitive string
 * comparison, matching the caseIgnoreMatch semantics used by the majority of LDAP schema attribute types.
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
        return $this->evaluateFilter($entry, $filter) === FilterResult::True;
    }

    private function evaluateFilter(
        Entry $entry,
        FilterInterface $filter,
    ): FilterResult {
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
    ): FilterResult {
        $hasUndefined = false;

        foreach ($filter->get() as $child) {
            $result = $this->evaluateFilter(
                $entry,
                $child,
            );
            if ($result === FilterResult::False) {
                return FilterResult::False;
            }
            if ($result === FilterResult::Undefined) {
                $hasUndefined = true;
            }
        }

        return $hasUndefined
            ? FilterResult::Undefined
            : FilterResult::True;
    }

    private function evaluateOr(
        Entry $entry,
        OrFilter $filter,
    ): FilterResult {
        $hasUndefined = false;

        foreach ($filter->get() as $child) {
            $result = $this->evaluateFilter(
                $entry,
                $child,
            );
            if ($result === FilterResult::True) {
                return FilterResult::True;
            }
            if ($result === FilterResult::Undefined) {
                $hasUndefined = true;
            }
        }

        return $hasUndefined
            ? FilterResult::Undefined
            : FilterResult::False;
    }

    private function evaluateNot(
        Entry $entry,
        NotFilter $filter,
    ): FilterResult {
        return match ($this->evaluateFilter($entry, $filter->get())) {
            FilterResult::True => FilterResult::False,
            FilterResult::False => FilterResult::True,
            FilterResult::Undefined => FilterResult::Undefined,
        };
    }

    private function evaluatePresent(
        Entry $entry,
        PresentFilter $filter,
    ): FilterResult {
        return $entry->has($filter->getAttribute())
            ? FilterResult::True
            : FilterResult::False;
    }

    private function evaluateEquality(
        Entry $entry,
        EqualityFilter $filter,
    ): FilterResult {
        $attribute = $entry->get($filter->getAttribute());

        if ($attribute === null) {
            return FilterResult::Undefined;
        }

        $filterValue = strtolower($filter->getValue());

        foreach ($attribute->getValues() as $value) {
            if (strtolower($value) === $filterValue) {
                return FilterResult::True;
            }
        }

        return FilterResult::False;
    }

    private function evaluateSubstring(
        Entry $entry,
        SubstringFilter $filter,
    ): FilterResult {
        $attribute = $entry->get($filter->getAttribute());

        if ($attribute === null) {
            return FilterResult::Undefined;
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
                return FilterResult::True;
            }
        }

        return FilterResult::False;
    }

    /**
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

        $endsWithStart = strlen($value) - strlen($endsWith);

        return $endsWithStart >= $pos && str_ends_with($value, $endsWith);
    }

    private function evaluateGreaterOrEqual(
        Entry $entry,
        GreaterThanOrEqualFilter $filter,
    ): FilterResult {
        $attribute = $entry->get($filter->getAttribute());

        if ($attribute === null) {
            return FilterResult::Undefined;
        }

        $filterValue = $filter->getValue();

        foreach ($attribute->getValues() as $value) {
            if ($this->compareOrdered($value, $filterValue) >= 0) {
                return FilterResult::True;
            }
        }

        return FilterResult::False;
    }

    private function evaluateLessOrEqual(
        Entry $entry,
        LessThanOrEqualFilter $filter,
    ): FilterResult {
        $attribute = $entry->get($filter->getAttribute());

        if ($attribute === null) {
            return FilterResult::Undefined;
        }

        $filterValue = $filter->getValue();

        foreach ($attribute->getValues() as $value) {
            if ($this->compareOrdered($value, $filterValue) <= 0) {
                return FilterResult::True;
            }
        }

        return FilterResult::False;
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
    ): FilterResult {
        $attribute = $entry->get($filter->getAttribute());

        if ($attribute === null) {
            return FilterResult::Undefined;
        }

        $filterValue = strtolower($filter->getValue());

        foreach ($attribute->getValues() as $value) {
            if (strtolower($value) === $filterValue) {
                return FilterResult::True;
            }
        }

        return FilterResult::False;
    }

    private function evaluateMatchingRule(
        Entry $entry,
        MatchingRuleFilter $filter,
    ): FilterResult {
        $filterValue = $filter->getValue();
        $values = $this->collectValuesToTest($entry, $filter);

        if ($values === []) {
            return FilterResult::Undefined;
        }

        foreach ($values as $value) {
            if ($this->matchByRule($filter->getMatchingRule(), $value, $filterValue)) {
                return FilterResult::True;
            }
        }

        return FilterResult::False;
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
            foreach ($entry->getAttributes() as $attribute) {
                $values = array_merge(
                    $values,
                    $attribute->getValues(),
                );
            }
        }

        if ($filter->getUseDnAttributes()) {
            $values = array_merge(
                $values,
                $this->collectDnValues(
                    $entry,
                    $filterAttributeName,
                ),
            );
        }

        return $values;
    }

    /**
     * Collects attribute values from all RDN components of the entry's DN.
     *
     * @return array<string>
     */
    private function collectDnValues(
        Entry $entry,
        ?string $filterAttributeName,
    ): array {
        $components = array_merge(
            ...array_map(
                fn ($rdn) => $rdn->getAll(),
                $entry->getDn()->toArray(),
            ),
        );

        if ($filterAttributeName !== null) {
            $components = array_filter(
                $components,
                fn ($component) => strcasecmp($component->getName(), $filterAttributeName) === 0,
            );
        }

        return array_map(
            fn ($component) => $component->getValue(),
            $components,
        );
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
