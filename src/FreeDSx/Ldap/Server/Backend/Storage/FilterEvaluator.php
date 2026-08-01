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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\IntegerComparator;
use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use FreeDSx\Ldap\Schema\Schema;
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
use WeakMap;

/**
 * Pure-PHP FilterEvaluatorInterface using RFC 4511 §4.5.1 three-valued logic.
 *
 * Uses schema-driven comparators with CaseIgnoreComparator as the default fallback per RFC 4511 §4.5.1.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class FilterEvaluator implements FilterEvaluatorInterface
{
    private const MATCHING_RULE_CASE_IGNORE = '2.5.13.2';

    private const MATCHING_RULE_CASE_EXACT = '2.5.13.5';

    private const MATCHING_RULE_BIT_AND = '1.2.840.113556.1.4.803';

    private const MATCHING_RULE_BIT_OR = '1.2.840.113556.1.4.804';

    /**
     * Flattened RDN components of the current entry's DN; scoped to one evaluate() call.
     *
     * @var array<\FreeDSx\Ldap\Entry\Rdn>|null
     */
    private ?array $cachedDnRdns = null;

    /**
     * Lowercased base name => first matching attribute; scoped to one evaluate() call.
     *
     * @var array<string, Attribute>|null
     */
    private ?array $attributeIndex = null;

    /**
     * @var WeakMap<object, SubstringAssertion>
     */
    private WeakMap $substringCache;

    /**
     * @var WeakMap<object, bool>
     */
    private WeakMap $orderedDigitCache;

    private readonly CaseIgnoreComparator $defaultComparator;

    private readonly IntegerComparator $integerComparator;

    public function __construct(private readonly ?Schema $schema = null)
    {
        $this->defaultComparator = new CaseIgnoreComparator();
        $this->integerComparator = new IntegerComparator();
        $this->substringCache = new WeakMap();
        $this->orderedDigitCache = new WeakMap();
    }

    public function evaluate(
        Entry $entry,
        FilterInterface $filter,
    ): bool {
        $this->cachedDnRdns = null;
        $this->attributeIndex = null;

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
                'Unrecognized filter type.',
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
        return $this->lookupAttribute($entry, $filter->getAttribute()) !== null
            ? FilterResult::True
            : FilterResult::False;
    }

    private function evaluateEquality(
        Entry $entry,
        EqualityFilter $filter,
    ): FilterResult {
        $attribute = $this->lookupAttribute($entry, $filter->getAttribute());

        if ($attribute === null) {
            return FilterResult::Undefined;
        }

        $comparator = $this->resolveEqualityComparator($filter->getAttribute());
        $filterValue = $filter->getValue();

        foreach ($attribute->getValues() as $value) {
            if ($comparator->equals($value, $filterValue)) {
                return FilterResult::True;
            }
        }

        return FilterResult::False;
    }

    private function evaluateSubstring(
        Entry $entry,
        SubstringFilter $filter,
    ): FilterResult {
        $attribute = $this->lookupAttribute($entry, $filter->getAttribute());

        if ($attribute === null) {
            return FilterResult::Undefined;
        }

        $comparator = $this->resolveSubstringComparator($filter->getAttribute());
        $assertion = $this->buildSubstringAssertion($filter);

        foreach ($attribute->getValues() as $value) {
            if ($comparator->substringMatches($value, $assertion)) {
                return FilterResult::True;
            }
        }

        return FilterResult::False;
    }

    private function evaluateGreaterOrEqual(
        Entry $entry,
        GreaterThanOrEqualFilter $filter,
    ): FilterResult {
        $attribute = $this->lookupAttribute($entry, $filter->getAttribute());

        if ($attribute === null) {
            return FilterResult::Undefined;
        }

        $filterValue = $filter->getValue();
        $comparator = $this->resolveOrderingComparator($filter->getAttribute());
        $filterIsDigit = $comparator === null && $this->orderedFilterValueIsDigit($filter);

        foreach ($attribute->getValues() as $value) {
            $cmp = $comparator?->compare($value, $filterValue)
                ?? $this->compareOrdered($value, $filterValue, $filterIsDigit);

            if ($cmp >= 0) {
                return FilterResult::True;
            }
        }

        return FilterResult::False;
    }

    private function evaluateLessOrEqual(
        Entry $entry,
        LessThanOrEqualFilter $filter,
    ): FilterResult {
        $attribute = $this->lookupAttribute($entry, $filter->getAttribute());

        if ($attribute === null) {
            return FilterResult::Undefined;
        }

        $filterValue = $filter->getValue();
        $comparator = $this->resolveOrderingComparator($filter->getAttribute());
        $filterIsDigit = $comparator === null && $this->orderedFilterValueIsDigit($filter);

        foreach ($attribute->getValues() as $value) {
            $cmp = $comparator?->compare($value, $filterValue)
                ?? $this->compareOrdered($value, $filterValue, $filterIsDigit);

            if ($cmp <= 0) {
                return FilterResult::True;
            }
        }

        return FilterResult::False;
    }

    private function compareOrdered(
        string $value,
        string $filterValue,
        bool $filterValueIsDigit,
    ): int {
        if ($filterValueIsDigit && ctype_digit($value)) {
            return (int) $value <=> (int) $filterValue;
        }

        return strcasecmp($value, $filterValue);
    }

    private function evaluateApproximate(
        Entry $entry,
        ApproximateFilter $filter,
    ): FilterResult {
        $attribute = $this->lookupAttribute($entry, $filter->getAttribute());

        if ($attribute === null) {
            return FilterResult::Undefined;
        }

        $filterValue = $filter->getValue();

        foreach ($attribute->getValues() as $value) {
            if ($this->defaultComparator->equals($value, $filterValue)) {
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
            $values = $this->lookupAttribute($entry, $filterAttributeName)?->getValues() ?? [];
        } else {
            foreach ($entry->getAttributes() as $attribute) {
                array_push(
                    $values,
                    ...$attribute->getValues(),
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
        $components = $this->cachedDnRdns
            ?? ($this->cachedDnRdns = array_merge(
                ...array_map(
                    fn($rdn) => $rdn->getAll(),
                    $entry->getDn()->toArray(),
                ),
            ));

        if ($filterAttributeName !== null) {
            $components = array_filter(
                $components,
                fn($component) => strcasecmp($component->getName(), $filterAttributeName) === 0,
            );
        }

        return array_map(
            fn($component) => $component->getValue(),
            $components,
        );
    }

    private function matchByRule(
        ?string $rule,
        string $value,
        string $filterValue,
    ): bool {
        if ($rule === null) {
            return $this->defaultComparator->equals(
                $value,
                $filterValue,
            );
        }

        $schemaComparator = $this->schema?->getComparator($rule);
        if ($schemaComparator !== null) {
            return $schemaComparator->equals(
                $value,
                $filterValue,
            );
        }

        return match ($rule) {
            self::MATCHING_RULE_CASE_IGNORE => strtolower($value) === strtolower($filterValue),
            self::MATCHING_RULE_CASE_EXACT => $value === $filterValue,
            self::MATCHING_RULE_BIT_AND => ((int) $value & (int) $filterValue) === (int) $filterValue,
            self::MATCHING_RULE_BIT_OR => ((int) $value & (int) $filterValue) !== 0,
            default => throw new OperationException(
                sprintf('Unsupported matching rule: %s', $rule),
                ResultCode::INAPPROPRIATE_MATCHING,
            ),
        };
    }

    private function resolveEqualityComparator(string $attrName): MatchingRuleComparatorInterface
    {
        if ($this->schema === null) {
            return $this->defaultComparator;
        }

        $attrType = $this->schema->getAttributeType($attrName);
        $comparator = $attrType?->equalityOid !== null
            ? $this->schema->getComparator($attrType->equalityOid)
            : null;

        return $comparator ?? $this->defaultComparator;
    }

    private function resolveSubstringComparator(string $attrName): MatchingRuleComparatorInterface
    {
        if ($this->schema === null) {
            return $this->defaultComparator;
        }

        $attrType = $this->schema->getAttributeType($attrName);
        $comparator = $attrType?->substringOid !== null
            ? $this->schema->getComparator($attrType->substringOid)
            : null;

        return $comparator ?? $this->defaultComparator;
    }

    /**
     * Returns null when schema is unavailable or the attribute is unknown — caller falls back to the digit heuristic.
     */
    private function resolveOrderingComparator(string $attrName): ?MatchingRuleComparatorInterface
    {
        if ($this->schema === null) {
            return null;
        }

        $attrType = $this->schema->getAttributeType($attrName);

        if ($attrType === null) {
            return null;
        }

        // An explicit, registered ordering rule wins
        $comparator = $attrType->orderingOid !== null
            ? $this->schema->getComparator($attrType->orderingOid)
            : null;

        if ($comparator !== null) {
            return $comparator;
        }

        // Otherwise infer numeric ordering from an INTEGER syntax, else order as a string.
        return $attrType->syntaxOid === SyntaxOid::OID_INTEGER
            ? $this->integerComparator
            : $this->defaultComparator;
    }

    private function buildSubstringAssertion(SubstringFilter $filter): SubstringAssertion
    {
        return $this->substringCache[$filter] ??= new SubstringAssertion(
            initial: $filter->getStartsWith(),
            any: array_values($filter->getContains()),
            final: $filter->getEndsWith(),
        );
    }

    /**
     * Defers to Entry::get() when the filter attribute has options, to preserve Attribute::equals() options-matching.
     */
    private function lookupAttribute(
        Entry $entry,
        string $filterAttributeName,
    ): ?Attribute {
        if (str_contains($filterAttributeName, ';')) {
            return $entry->get($filterAttributeName);
        }

        if ($this->attributeIndex === null) {
            $index = [];
            foreach ($entry->getAttributes() as $attr) {
                $lc = strtolower($attr->getName());
                $index[$lc] ??= $attr;
            }
            $this->attributeIndex = $index;
        }

        return $this->attributeIndex[strtolower($filterAttributeName)] ?? null;
    }

    private function orderedFilterValueIsDigit(
        GreaterThanOrEqualFilter|LessThanOrEqualFilter $filter,
    ): bool {
        return $this->orderedDigitCache[$filter] ??= ctype_digit($filter->getValue());
    }
}
