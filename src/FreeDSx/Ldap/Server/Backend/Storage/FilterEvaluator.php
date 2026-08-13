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
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\IntegerComparator;
use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\ApproximateFilter;
use FreeDSx\Ldap\Search\Filter\AttributeValueAssertionInterface;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\FilterAttributeInterface;
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
    use EntryDnAttributeTrait;

    private const MATCHING_RULE_CASE_IGNORE = '2.5.13.2';

    private const MATCHING_RULE_CASE_EXACT = '2.5.13.5';

    private const MATCHING_RULE_BIT_AND = '1.2.840.113556.1.4.803';

    private const MATCHING_RULE_BIT_OR = '1.2.840.113556.1.4.804';

    /**
     * Flattened RDN components of the current entry's DN; scoped to one evaluate() call.
     *
     * @var array<Rdn>|null
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
    private WeakMap $assertionSyntaxCache;

    /**
     * @var WeakMap<object, bool>
     */
    private WeakMap $recognizedAttributeCache;

    /**
     * Resolved SUBSTR rule OID per filter, with false standing for a type that declares none.
     *
     * @var WeakMap<object, string|false>
     */
    private WeakMap $substringRuleCache;

    private readonly CaseIgnoreComparator $defaultComparator;

    private readonly IntegerComparator $integerComparator;

    private readonly AttributeSyntaxResolver $syntaxResolver;

    public function __construct(private readonly Schema $schema)
    {
        $this->defaultComparator = new CaseIgnoreComparator();
        $this->integerComparator = new IntegerComparator();
        $this->syntaxResolver = new AttributeSyntaxResolver($schema);
        $this->substringCache = new WeakMap();
        $this->assertionSyntaxCache = new WeakMap();
        $this->recognizedAttributeCache = new WeakMap();
        $this->substringRuleCache = new WeakMap();
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
        if ($filter instanceof FilterAttributeInterface && !$this->attributeIsRecognized($filter)) {
            return FilterResult::Undefined;
        }

        return match (true) {
            $filter instanceof AndFilter => $this->evaluateAnd($entry, $filter),
            $filter instanceof OrFilter => $this->evaluateOr($entry, $filter),
            $filter instanceof NotFilter => $this->evaluateNot($entry, $filter),
            $filter instanceof PresentFilter => $this->evaluatePresent($entry, $filter),
            $filter instanceof EqualityFilter => $this->evaluateEquality($entry, $filter),
            $filter instanceof SubstringFilter => $this->evaluateSubstring($entry, $filter),
            $filter instanceof GreaterThanOrEqualFilter,
            $filter instanceof LessThanOrEqualFilter => $this->evaluateOrdered($entry, $filter),
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
        // RFC 4511 4.5.1.7.5: true when the type or a subtype of it is present.
        return $this->valuesForAssertion($entry, $filter->getAttribute()) !== []
            ? FilterResult::True
            : FilterResult::False;
    }

    private function evaluateEquality(
        Entry $entry,
        EqualityFilter $filter,
    ): FilterResult {
        if (!$this->assertionSyntaxIsValid($filter)) {
            return FilterResult::Undefined;
        }

        $values = $this->valuesForAssertion(
            $entry,
            $filter->getAttribute(),
        );

        // A type the schema defines but the entry lacks is False; an undefined type was answered upstream.
        if ($values === []) {
            return FilterResult::False;
        }

        $comparator = $this->resolveEqualityComparator($filter->getAttribute());
        $filterValue = $filter->getValue();

        foreach ($values as $value) {
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
        // RFC 4511 4.5.1.7: the rule a substring item applies is the type's SUBSTR, so a type declaring none has
        // no way to answer the assertion and the item is Undefined.
        $substringRuleOid = $this->substringRuleOid($filter);

        if ($substringRuleOid === null) {
            return FilterResult::Undefined;
        }

        $values = $this->valuesForAssertion($entry, $filter->getAttribute());

        // A type the schema defines but the entry lacks is False; an undefined type was answered upstream.
        if ($values === []) {
            return FilterResult::False;
        }

        $comparator = $this->schema->getComparator($substringRuleOid)
            ?? $this->defaultComparator;
        $assertion = $this->buildSubstringAssertion($filter);

        foreach ($values as $value) {
            if ($comparator->substringMatches($value, $assertion)) {
                return FilterResult::True;
            }
        }

        return FilterResult::False;
    }

    /**
     * Both ordered filters agree on everything but the direction of the final comparison.
     */
    private function evaluateOrdered(
        Entry $entry,
        GreaterThanOrEqualFilter|LessThanOrEqualFilter $filter,
    ): FilterResult {
        if (!$this->assertionSyntaxIsValid($filter)) {
            return FilterResult::Undefined;
        }

        $values = $this->valuesForAssertion(
            $entry,
            $filter->getAttribute(),
        );

        // A type the schema defines but the entry lacks is False; an undefined type was answered upstream.
        if ($values === []) {
            return FilterResult::False;
        }

        $filterValue = $filter->getValue();
        $comparator = $this->resolveOrderingComparator($filter->getAttribute());
        $atLeast = $filter instanceof GreaterThanOrEqualFilter;

        foreach ($values as $value) {
            $cmp = $comparator->compare($value, $filterValue);

            if ($atLeast ? $cmp >= 0 : $cmp <= 0) {
                return FilterResult::True;
            }
        }

        return FilterResult::False;
    }

    private function evaluateApproximate(
        Entry $entry,
        ApproximateFilter $filter,
    ): FilterResult {
        if (!$this->assertionSyntaxIsValid($filter)) {
            return FilterResult::Undefined;
        }

        $values = $this->valuesForAssertion($entry, $filter->getAttribute());

        // A type the schema defines but the entry lacks is False; an undefined type was answered upstream.
        if ($values === []) {
            return FilterResult::False;
        }

        // No approximate rule is implemented, so this falls back to the type's own equality rather than a case
        // insensitive default, which would answer differently than the equality filter for the same assertion.
        $comparator = $this->resolveEqualityComparator($filter->getAttribute());
        $filterValue = $filter->getValue();

        foreach ($values as $value) {
            if ($comparator->equals($value, $filterValue)) {
                return FilterResult::True;
            }
        }

        return FilterResult::False;
    }

    private function evaluateMatchingRule(
        Entry $entry,
        MatchingRuleFilter $filter,
    ): FilterResult {
        // RFC 4511 4.5.1.7: an unrecognized rule makes the item Undefined, and a server must not answer with an error.
        $matcher = $this->resolveRuleMatcher(
            $filter->getMatchingRule(),
            $filter->getAttribute(),
        );

        if ($matcher === null) {
            return FilterResult::Undefined;
        }

        $filterValue = $filter->getValue();
        $values = $this->collectValuesToTest($entry, $filter);

        if ($values === []) {
            return FilterResult::False;
        }

        foreach ($values as $value) {
            if ($matcher($value, $filterValue)) {
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
            $values = self::isEntryDnAttribute($filterAttributeName)
                ? [$entry->getDn()->toString()]
                : $this->lookupAttribute($entry, $filterAttributeName)?->getValues() ?? [];
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

        // RDN values carry their escaping, which is a property of the DN string rather than of the value asserted.
        return array_map(
            fn($component) => Rdn::unescape($component->getValue()),
            $components,
        );
    }

    /**
     * Resolve the assertion for a rule or null when the rule cannot be applied, so the item is Undefined.
     *
     * @return null|callable(string, string): bool
     */
    private function resolveRuleMatcher(
        ?string $rule,
        ?string $attribute,
    ): ?callable {
        // RFC 4511 4.5.1.7.7: an absent matchingRule means the EQUALITY rule of the attribute type.
        if ($rule === null) {
            $comparator = $attribute !== null
                ? $this->resolveEqualityComparator($attribute)
                : $this->defaultComparator;

            return $comparator->equals(...);
        }

        $schemaComparator = $this->schema->getComparator($rule);
        if ($schemaComparator !== null) {
            return $schemaComparator->equals(...);
        }

        return match ($rule) {
            self::MATCHING_RULE_CASE_IGNORE => static fn(string $v, string $a): bool
                => strtolower($v) === strtolower($a),
            self::MATCHING_RULE_CASE_EXACT => static fn(string $v, string $a): bool
                => $v === $a,
            self::MATCHING_RULE_BIT_AND => static fn(string $v, string $a): bool
                => ((int) $v & (int) $a) === (int) $a,
            self::MATCHING_RULE_BIT_OR => static fn(string $v, string $a): bool
                => ((int) $v & (int) $a) !== 0,
            default => null,
        };
    }

    private function resolveEqualityComparator(string $attrName): MatchingRuleComparatorInterface
    {
        $attrType = $this->schema->getAttributeType($attrName);
        $comparator = $attrType?->equalityOid !== null
            ? $this->schema->getComparator($attrType->equalityOid)
            : null;

        return $comparator ?? $this->defaultComparator;
    }

    /**
     * Returns null when the attribute is unknown, so the caller falls back to the digit heuristic.
     */
    private function resolveOrderingComparator(string $attrName): MatchingRuleComparatorInterface
    {
        $attrType = $this->schema->getAttributeType($attrName);

        if ($attrType === null) {
            return $this->defaultComparator;
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
     * Whether a description carries options, without paying for an Attribute to ask Attribute::hasOptions().
     */
    private static function descriptionHasOptions(string $attributeDescription): bool
    {
        return str_contains($attributeDescription, ';');
    }

    /**
     * Defers to Entry::get() when the filter attribute has options to preserve Attribute::equals() options-matching.
     */
    private function lookupAttribute(
        Entry $entry,
        string $filterAttributeName,
    ): ?Attribute {
        if (self::descriptionHasOptions($filterAttributeName)) {
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

    /**
     * Every value an assertion on this description must be tested against.
     *
     * RFC 4512 2.5.2 makes an assertion on an attribute type cover its tagged variants and its subtypes.
     *
     * @return array<string>
     */
    private function valuesForAssertion(
        Entry $entry,
        string $filterAttributeName,
    ): array {
        // RFC 5020: derived from the entry, so it is matchable whether or not the request asked for it.
        if (self::isEntryDnAttribute($filterAttributeName)) {
            return [$entry->getDn()->toString()];
        }

        if (self::descriptionHasOptions($filterAttributeName)) {
            return $entry->get($filterAttributeName)?->getValues() ?? [];
        }

        $wanted = strtolower($filterAttributeName);
        $values = [];

        foreach ($entry->getAttributes() as $attribute) {
            if ($this->describesSameType($attribute->getName(), $wanted)) {
                array_push($values, ...$attribute->getValues());
            }
        }

        return $values;
    }

    /**
     * Whether an entry attribute is the wanted type, or a subtype of it through the SUP chain.
     */
    private function describesSameType(
        string $entryAttributeName,
        string $wantedLowerName,
    ): bool {
        if (strtolower($entryAttributeName) === $wantedLowerName) {
            return true;
        }

        return $this->schema->isTypeOrSubtypeOf(
            $entryAttributeName,
            $wantedLowerName,
        );
    }

    /**
     * An attribute description the schema does not define makes the item Undefined (RFC 4511 4.5.1.7), whether or
     * not an entry happens to carry values under that name.
     *
     * The answer depends only on the filter, so it is memoized rather than recomputed for every entry tested.
     */
    private function attributeIsRecognized(FilterAttributeInterface $filter): bool
    {
        return $this->recognizedAttributeCache[$filter] ??= $this->schemaDefines($filter->getAttribute());
    }

    /**
     * An extensibleMatch may name no type at all, which this rule has nothing to say about.
     */
    private function schemaDefines(?string $attributeDescription): bool
    {
        if ($attributeDescription === null) {
            return true;
        }

        return self::isEntryDnAttribute($attributeDescription)
            || $this->schema->getAttributeType(Attribute::normalizeName($attributeDescription)) !== null;
    }

    /**
     * An assertion value that does not conform to the type's syntax makes the item Undefined (RFC 4511 4.5.1.7).
     *
     * The answer depends only on the filter, so it is memoized rather than recomputed for every entry tested.
     */
    private function assertionSyntaxIsValid(AttributeValueAssertionInterface $filter): bool
    {
        return $this->assertionSyntaxCache[$filter] ??= $this->syntaxResolver->conforms(
            $filter->getAttribute(),
            $filter->getValue(),
        );
    }

    /**
     * The SUBSTR rule the filter's type resolves to, or null when it declares none.
     *
     * The answer depends only on the filter, so it is memoized rather than recomputed for every entry tested.
     */
    private function substringRuleOid(SubstringFilter $filter): ?string
    {
        $ruleOid = $this->substringRuleCache[$filter] ??= $this->schema->getSubstringRuleOid(
            Attribute::normalizeName($filter->getAttribute()),
        ) ?? false;

        return $ruleOid === false
            ? null
            : $ruleOid;
    }
}
