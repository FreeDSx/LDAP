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

namespace FreeDSx\Ldap\Server\Backend\Storage\Filter;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\MatchingRuleOid;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Schema\Matching\CanonicalIndexKeyInterface;
use FreeDSx\Ldap\Schema\Matching\Comparator\BitMaskComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreComparator;
use FreeDSx\Ldap\Schema\Matching\EqualityComparatorResolver;
use FreeDSx\Ldap\Schema\Matching\Comparator\IntegerComparator;
use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;
use FreeDSx\Ldap\Schema\Validation\Syntax\OidSyntaxValidator;
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
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedAttributeTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedResolver;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\Evaluation\FilterEvaluation;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\Evaluation\FilterPlan;
use FreeDSx\Ldap\Server\Utility\Memo\BoundedMemo;
use FreeDSx\Ldap\Server\Utility\Memo\MemoScope;
use Closure;
use WeakMap;

use function array_filter;
use function array_map;
use function array_merge;
use function array_push;
use function array_values;
use function is_string;
use function spl_object_id;
use function str_contains;
use function strcasecmp;
use function strtolower;

/**
 * Pure-PHP FilterEvaluatorInterface using RFC 4511 §4.5.1 three-valued logic.
 *
 * Uses schema-driven comparators with CaseIgnoreComparator as the default fallback per RFC 4511 §4.5.1.
 *
 * Note: A filter must not be changed once it has been evaluated, as what its items need is planned once per filter.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class FilterEvaluator implements FilterEvaluatorInterface
{
    use DerivedAttributeTrait;

    private const MATCHING_RULE_CASE_IGNORE = '2.5.13.2';

    private const MATCHING_RULE_CASE_EXACT = '2.5.13.5';

    private const MATCHING_RULE_BIT_AND = '1.2.840.113556.1.4.803';

    private const MATCHING_RULE_BIT_OR = '1.2.840.113556.1.4.804';

    private const MAX_REMEMBERED_DESCRIPTIONS = 1024;

    /**
     * Assertion answers are kept for this many attribute descriptions or rules, each holding the values below.
     */
    private const MAX_REMEMBERED_NAMES = 64;

    private const MAX_REMEMBERED_VALUES = 64;

    /**
     * Whether the schema defines each attribute description a filter names.
     *
     * @var BoundedMemo<string, bool>
     */
    private readonly BoundedMemo $recognizedDescriptions;

    /**
     * The derived attribute each description names, with false standing for one that names none.
     *
     * @var BoundedMemo<string, string|false>
     */
    private readonly BoundedMemo $derivedNames;

    /**
     * The SUBSTR rule OID each description's type resolves to, with false standing for a type that declares none.
     *
     * @var BoundedMemo<string, string|false>
     */
    private readonly BoundedMemo $substringRules;

    /**
     * Whether each assertion value conforms to its attribute's syntax, by description then value.
     *
     * @var BoundedMemo<string, BoundedMemo<string, bool>>
     */
    private readonly BoundedMemo $conformingValues;

    /**
     * Whether each equality assertion value is valid for its attribute, by description then value.
     *
     * @var BoundedMemo<string, BoundedMemo<string, bool>>
     */
    private readonly BoundedMemo $validAssertions;

    /**
     * Whether each extensible match value conforms to its rule's syntax, by rule then value.
     *
     * @var BoundedMemo<string, BoundedMemo<string, bool>>
     */
    private readonly BoundedMemo $ruleConformingValues;

    /**
     * The plan of each filter being evaluated, kept by the filter itself and dropped with it.
     *
     * @var WeakMap<FilterInterface, FilterPlan>
     */
    private readonly WeakMap $plans;

    private readonly AttributeSyntaxResolver $syntaxResolver;

    public function __construct(
        private readonly Schema $schema,
        private readonly DerivedResolver $derivedResolver,
        private readonly EqualityComparatorResolver $equalityResolver,
        ?AttributeSyntaxResolver $syntaxResolver = null,
        private readonly CaseIgnoreComparator $defaultComparator = new CaseIgnoreComparator(),
        private readonly IntegerComparator $integerComparator = new IntegerComparator(),
    ) {
        $this->syntaxResolver = $syntaxResolver ?? new AttributeSyntaxResolver($schema);
        $this->recognizedDescriptions = new BoundedMemo(
            self::MAX_REMEMBERED_DESCRIPTIONS,
            MemoScope::Process,
            $this->schemaDefines(...),
        );
        $this->derivedNames = new BoundedMemo(
            self::MAX_REMEMBERED_DESCRIPTIONS,
            MemoScope::Process,
            static fn(string $description): string|false => self::derivedTypeName($description) ?? false,
        );
        $this->substringRules = new BoundedMemo(
            self::MAX_REMEMBERED_DESCRIPTIONS,
            MemoScope::Process,
            fn(string $description): string|false => $this->schema->getSubstringRuleOid(
                Attribute::normalizeName($description),
            ) ?? false,
        );
        $this->conformingValues = self::answersByValue($this->syntaxResolver->conforms(...));
        $this->validAssertions = self::answersByValue($this->assertionValueIsValid(...));
        $this->ruleConformingValues = self::answersByValue($this->ruleValueConforms(...));
        $this->plans = new WeakMap();
    }

    public function evaluate(
        Entry $entry,
        FilterInterface $filter,
    ): bool {
        $evaluation = new FilterEvaluation(
            $entry,
            $this->plans[$filter] ??= new FilterPlan(),
        );

        $result = $this->evaluateFilter(
            $evaluation,
            $filter,
        );

        return $result === FilterResult::True;
    }

    /**
     * The same preconditions evaluation applies, asked without an entry so a caller can answer each cause its own way.
     */
    public function undefinedCause(FilterInterface $filter): ?UndefinedCause
    {
        if ($filter instanceof FilterAttributeInterface && !$this->attributeIsRecognized($filter)) {
            return UndefinedCause::UnrecognizedAttributeType;
        }
        if (!$filter instanceof AttributeValueAssertionInterface) {
            return null;
        }

        return $this->assertionIsValid($filter)
            ? null
            : UndefinedCause::InvalidAssertionValue;
    }

    private function evaluateFilter(
        FilterEvaluation $evaluation,
        FilterInterface $filter,
    ): FilterResult {
        if ($filter instanceof FilterAttributeInterface && !$this->attributeIsRecognized($filter)) {
            return FilterResult::Undefined;
        }

        return match (true) {
            $filter instanceof AndFilter => $this->evaluateAnd(
                $evaluation,
                $filter,
            ),
            $filter instanceof OrFilter => $this->evaluateOr(
                $evaluation,
                $filter,
            ),
            $filter instanceof NotFilter => $this->evaluateNot(
                $evaluation,
                $filter,
            ),
            $filter instanceof PresentFilter => $this->evaluatePresent(
                $evaluation,
                $filter,
            ),
            // RFC 4511 4.5.1.7.6: with no approximate rule implemented, an approximate item is treated as equality.
            $filter instanceof EqualityFilter,
            $filter instanceof ApproximateFilter => $this->evaluateEquality(
                $evaluation,
                $filter,
            ),
            $filter instanceof SubstringFilter => $this->evaluateSubstring(
                $evaluation,
                $filter,
            ),
            $filter instanceof GreaterThanOrEqualFilter,
            $filter instanceof LessThanOrEqualFilter => $this->evaluateOrdered(
                $evaluation,
                $filter,
            ),
            $filter instanceof MatchingRuleFilter => $this->evaluateMatchingRule(
                $evaluation,
                $filter,
            ),
            default => throw new OperationException(
                'Unrecognized filter type.',
                ResultCode::PROTOCOL_ERROR,
            ),
        };
    }

    private function evaluateAnd(
        FilterEvaluation $evaluation,
        AndFilter $filter,
    ): FilterResult {
        $hasUndefined = false;

        foreach ($filter->get() as $child) {
            $result = $this->evaluateFilter(
                $evaluation,
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
        FilterEvaluation $evaluation,
        OrFilter $filter,
    ): FilterResult {
        $id = spl_object_id($filter);
        $plan = $evaluation->plan;
        $keySets = $this->keySetsOf(
            $plan,
            $id,
            $filter,
        );

        foreach ($keySets as $description => $keys) {
            $holdsAny = $this->holdsAnyKey(
                $evaluation,
                $description,
                $keys,
            );

            if ($holdsAny) {
                return FilterResult::True;
            }
        }
        $hasUndefined = false;

        foreach ($plan->ungrouped[$id] ?? $filter->get() as $child) {
            $result = $this->evaluateFilter(
                $evaluation,
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
        FilterEvaluation $evaluation,
        NotFilter $filter,
    ): FilterResult {
        $result = $this->evaluateFilter(
            $evaluation,
            $filter->get(),
        );

        return match ($result) {
            FilterResult::True => FilterResult::False,
            FilterResult::False => FilterResult::True,
            FilterResult::Undefined => FilterResult::Undefined,
        };
    }

    private function evaluatePresent(
        FilterEvaluation $evaluation,
        PresentFilter $filter,
    ): FilterResult {
        // RFC 4511 4.5.1.7.5: true when the type or a subtype of it is present.
        $values = $this->valuesOf(
            $evaluation,
            $filter->getAttribute(),
        );

        return $values !== []
            ? FilterResult::True
            : FilterResult::False;
    }

    private function evaluateEquality(
        FilterEvaluation $evaluation,
        EqualityFilter|ApproximateFilter $filter,
    ): FilterResult {
        $prepared = $evaluation->plan->equalities[spl_object_id($filter)] ??= $this->prepareEquality($filter);

        if ($prepared === false) {
            return FilterResult::Undefined;
        }
        $description = $filter->getAttribute();
        $values = $this->valuesOf(
            $evaluation,
            $description,
        );

        // A type the schema defines but the entry lacks is False; an undefined type was answered upstream.
        if ($values === []) {
            return FilterResult::False;
        }
        $comparator = $this->equalityResolver->for($description);

        if (is_string($prepared) && $comparator instanceof CanonicalIndexKeyInterface) {
            $holdsKey = $this->holdsKey(
                $evaluation,
                $description,
                $prepared,
                $comparator,
            );

            return $holdsKey
                ? FilterResult::True
                : FilterResult::False;
        }

        foreach ($values as $value) {
            $matches = $comparator->equals(
                $value,
                $filter->getValue(),
            );

            if ($matches) {
                return FilterResult::True;
            }
        }

        return FilterResult::False;
    }

    /**
     * The assertion's canonical key, true when its rule compares without one, or false when the item is Undefined.
     */
    private function prepareEquality(EqualityFilter|ApproximateFilter $filter): string|bool
    {
        if (!$this->assertionIsValid($filter)) {
            return false;
        }
        $comparator = $this->equalityResolver->for($filter->getAttribute());

        return $comparator instanceof CanonicalIndexKeyInterface
            ? $comparator->indexKey($filter->getValue()) ?? true
            : true;
    }

    /**
     * Keys are computed until one matches, and kept for the entry only once every value has been keyed.
     */
    private function holdsKey(
        FilterEvaluation $evaluation,
        string $description,
        string $key,
        CanonicalIndexKeyInterface $comparator,
    ): bool {
        if (isset($evaluation->keys[$description])) {
            return isset($evaluation->keys[$description][$key]);
        }
        $keys = [];
        $values = $this->valuesOf(
            $evaluation,
            $description,
        );

        foreach ($values as $value) {
            $valueKey = $comparator->indexKey($value);

            if ($valueKey === $key) {
                return true;
            }
            if ($valueKey !== null) {
                $keys[$valueKey] = true;
            }
        }
        $evaluation->keys[$description] = $keys;

        return false;
    }

    /**
     * @param array<int|string, true> $keys
     */
    private function holdsAnyKey(
        FilterEvaluation $evaluation,
        string $description,
        array $keys,
    ): bool {
        $held = $evaluation->keys[$description] ?? $this->heldKeys(
            $evaluation,
            $description,
        );

        foreach ($held as $key => $_) {
            if (isset($keys[$key])) {
                return true;
            }
        }

        return false;
    }

    /**
     * The canonical keys of every value the description selects, under its equality rule.
     *
     * @return array<int|string, true>
     */
    private function heldKeys(
        FilterEvaluation $evaluation,
        string $description,
    ): array {
        $comparator = $this->equalityResolver->for($description);
        $keys = [];
        $values = $this->valuesOf(
            $evaluation,
            $description,
        );

        foreach ($values as $value) {
            $key = $comparator instanceof CanonicalIndexKeyInterface
                ? $comparator->indexKey($value)
                : null;

            if ($key !== null) {
                $keys[$key] = true;
            }
        }

        return $evaluation->keys[$description] = $keys;
    }

    /**
     * A filter evaluated only once never pays for grouping, which starts on an OR's second evaluation.
     *
     * @return array<string, array<int|string, true>>
     */
    private function keySetsOf(
        FilterPlan $plan,
        int $id,
        OrFilter $filter,
    ): array {
        $keySets = $plan->keySets[$id] ?? null;

        if ($keySets === null) {
            $plan->keySets[$id] = false;

            return [];
        }

        if ($keySets === false) {
            return $plan->keySets[$id] = $this->groupEqualities(
                $plan,
                $id,
                $filter,
            );
        }

        return $keySets;
    }

    /**
     * Equality items that share an attribute and a canonical rule merge into one set of keys.
     *
     * @return array<string, array<int|string, true>>
     */
    private function groupEqualities(
        FilterPlan $plan,
        int $id,
        OrFilter $filter,
    ): array {
        $children = $filter->get();
        $asserted = [];

        foreach ($children as $child) {
            if ($child instanceof EqualityFilter || $child instanceof ApproximateFilter) {
                $description = $child->getAttribute();
                $asserted[$description] = ($asserted[$description] ?? 0) + 1;
            }
        }
        $keySets = [];
        $ungrouped = [];

        foreach ($children as $child) {
            $isShared = ($child instanceof EqualityFilter || $child instanceof ApproximateFilter)
                && $asserted[$child->getAttribute()] > 1;
            $key = $isShared
                ? $this->groupableKey(
                    $plan,
                    $child,
                )
                : null;

            if ($key === null) {
                $ungrouped[] = $child;

                continue;
            }
            $keySets[$child->getAttribute()][$key] = true;
        }

        if ($keySets !== []) {
            $plan->ungrouped[$id] = $ungrouped;
        }

        return $keySets;
    }

    /**
     * The item's canonical key, or null when it is Undefined or its rule compares without one.
     */
    private function groupableKey(
        FilterPlan $plan,
        EqualityFilter|ApproximateFilter $item,
    ): ?string {
        if (!$this->attributeIsRecognized($item)) {
            return null;
        }
        $prepared = $plan->equalities[spl_object_id($item)] ??= $this->prepareEquality($item);

        return is_string($prepared)
            ? $prepared
            : null;
    }

    private function evaluateSubstring(
        FilterEvaluation $evaluation,
        SubstringFilter $filter,
    ): FilterResult {
        // RFC 4511 4.5.1.7: the rule a substring item applies is the type's SUBSTR, so a type declaring none has
        // no way to answer the assertion and the item is Undefined.
        $substringRuleOid = $this->substringRuleOid($filter);

        if ($substringRuleOid === null) {
            return FilterResult::Undefined;
        }

        $values = $this->valuesOf(
            $evaluation,
            $filter->getAttribute(),
        );

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
        FilterEvaluation $evaluation,
        GreaterThanOrEqualFilter|LessThanOrEqualFilter $filter,
    ): FilterResult {
        $isValid = $evaluation->plan->validItems[spl_object_id($filter)] ??= $this->assertionSyntaxIsValid($filter);

        if (!$isValid) {
            return FilterResult::Undefined;
        }

        $values = $this->valuesOf(
            $evaluation,
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

    private function evaluateMatchingRule(
        FilterEvaluation $evaluation,
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

        $isValid = $evaluation->plan->validItems[spl_object_id($filter)] ??= $this->ruleAssertionIsValid($filter);

        if (!$isValid) {
            return FilterResult::Undefined;
        }

        $filterValue = $filter->getValue();
        $values = $this->collectValuesToTest(
            $evaluation,
            $filter,
        );

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
        FilterEvaluation $evaluation,
        MatchingRuleFilter $filter,
    ): array {
        $filterAttributeName = $filter->getAttribute();
        $values = [];

        if ($filterAttributeName !== null) {
            $values = $this->valuesOf(
                $evaluation,
                $filterAttributeName,
            );
        } else {
            foreach ($evaluation->entry->getAttributes() as $attribute) {
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
                    $evaluation->entry,
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
                fn($rdn) => $rdn->getAll(),
                $entry->getDn()->toArray(),
            ),
        );

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
                ? $this->equalityResolver->for($attribute)
                : $this->defaultComparator;

            return $comparator->equals(...);
        }

        $schemaComparator = $this->schema->getComparator($rule);
        if ($schemaComparator !== null) {
            return $this->schemaRuleMatcher(
                $rule,
                $schemaComparator,
            );
        }

        return match ($rule) {
            self::MATCHING_RULE_CASE_IGNORE => static fn(string $v, string $a): bool
                => strtolower($v) === strtolower($a),
            self::MATCHING_RULE_CASE_EXACT => static fn(string $v, string $a): bool
                => $v === $a,
            self::MATCHING_RULE_BIT_AND => (new BitMaskComparator(requireAllBits: true))->equals(...),
            self::MATCHING_RULE_BIT_OR => (new BitMaskComparator(requireAllBits: false))->equals(...),
            default => null,
        };
    }

    /**
     * @return null|callable(string, string): bool
     */
    private function schemaRuleMatcher(
        string $rule,
        MatchingRuleComparatorInterface $comparator,
    ): ?callable {
        if ($this->schema->isSubstringRule($rule)) {
            return null;
        }

        // RFC 4517: an ordering rule is TRUE when the attribute value is less than the assertion value.
        if ($this->schema->isOrderingRule($rule)) {
            return static fn(string $value, string $assertion): bool => $comparator->compare(
                $value,
                $assertion,
            ) < 0;
        }

        return $comparator->equals(...);
    }

    /**
     * Implementations disagree on whether a missing rule is undefined, so the permissive reading is taken.
     */
    private function resolveOrderingComparator(string $attrName): MatchingRuleComparatorInterface
    {
        if ($this->schema->getAttributeType($attrName) === null) {
            return $this->defaultComparator;
        }

        // An explicit, registered ordering rule wins
        $orderingOid = $this->schema->getOrderingRuleOid($attrName);
        $comparator = $orderingOid !== null
            ? $this->schema->getComparator($orderingOid)
            : null;

        if ($comparator !== null) {
            return $comparator;
        }

        // Otherwise infer numeric ordering from an INTEGER syntax, else order as a string.
        return $this->schema->getSyntaxOid($attrName) === SyntaxOid::OID_INTEGER
            ? $this->integerComparator
            : $this->defaultComparator;
    }

    private function buildSubstringAssertion(SubstringFilter $filter): SubstringAssertion
    {
        return new SubstringAssertion(
            initial: $filter->getStartsWith(),
            any: array_values($filter->getContains()),
            final: $filter->getEndsWith(),
        );
    }

    /**
     * @return array<string>
     */
    private function valuesOf(
        FilterEvaluation $evaluation,
        string $description,
    ): array {
        return $evaluation->values[$description] ??= $this->valuesForAssertion(
            $evaluation->entry,
            $description,
        );
    }

    /**
     * Every value an assertion on this description must be tested against.
     *
     * RFC 4512 2.5.2.1 makes an assertion cover every description whose type descends from the asserted one and
     * whose options include the asserted ones.
     *
     * @return array<string>
     */
    private function valuesForAssertion(
        Entry $entry,
        string $filterAttributeName,
    ): array {
        // The filter may spell the type as a name or an OID, so it is canonicalized before being resolved.
        $derivedName = $this->derivedNames->for($filterAttributeName);

        if ($derivedName !== false) {
            return [
                $this->derivedResolver->resolve(
                    $derivedName,
                    $entry,
                ),
            ];
        }
        // With no options asserted, one set of type names answers for every stored attribute.
        if (!str_contains($filterAttributeName, ';')) {
            return $this->valuesUnderTypes(
                $entry,
                $this->schema->typeAndSubtypeNames($filterAttributeName),
            );
        }
        $values = [];

        foreach ($entry->getAttributes() as $attribute) {
            if ($this->schema->isDescriptionSubtypeOf($attribute->getDescription(), $filterAttributeName)) {
                array_push(
                    $values,
                    ...$attribute->getValues(),
                );
            }
        }

        return $values;
    }

    /**
     * @param array<string, true> $names Lowercased type names and OIDs.
     * @return array<string>
     */
    private function valuesUnderTypes(
        Entry $entry,
        array $names,
    ): array {
        $values = [];

        foreach ($entry->getAttributes() as $attribute) {
            if (isset($names[strtolower($attribute->getName())])) {
                array_push(
                    $values,
                    ...$attribute->getValues(),
                );
            }
        }

        return $values;
    }

    /**
     * An attribute description the schema does not define makes the item Undefined (RFC 4511 4.5.1.7), whether or
     * not an entry happens to carry values under that name.
     */
    private function attributeIsRecognized(FilterAttributeInterface $filter): bool
    {
        $description = $filter->getAttribute();

        // An extensibleMatch may name no type at all.
        return $description === null || $this->recognizedDescriptions->for($description);
    }

    private function schemaDefines(string $attributeDescription): bool
    {
        // RFC 4511 4.5.1.7: a malformed description makes its item Undefined.
        if (!Attribute::isValidDescription($attributeDescription)) {
            return false;
        }

        return self::describesAnyDerivedAttribute($attributeDescription)
            || $this->schema->getAttributeType(Attribute::normalizeName($attributeDescription)) !== null;
    }

    /**
     * An assertion value that does not conform to the type's syntax makes the item Undefined (RFC 4511 4.5.1.7).
     */
    private function assertionSyntaxIsValid(AttributeValueAssertionInterface $filter): bool
    {
        return $this->conformingValues->for($filter->getAttribute())->for($filter->getValue());
    }

    /**
     * RFC 4511 4.5.1.7.7: the rule determines the assertion syntax, and a value that does not conform is Undefined.
     */
    private function ruleAssertionIsValid(MatchingRuleFilter $filter): bool
    {
        $rule = $filter->getMatchingRule();
        $attribute = $filter->getAttribute();

        if ($rule !== null) {
            return $this->ruleConformingValues->for($rule)->for($filter->getValue());
        }

        return $attribute === null || $this->conformingValues->for($attribute)->for($filter->getValue());
    }

    private function ruleValueConforms(
        string $rule,
        string $value,
    ): bool {
        $syntaxOid = $this->schema->getMatchingRule($rule)?->syntaxOid;

        return $syntaxOid === null || $this->syntaxResolver->conformsToSyntax(
            $syntaxOid,
            $value,
        );
    }

    /**
     * A value that does not conform to the type's syntax, or an OID naming a descriptor the schema does not define, is
     * Undefined (RFC 4511 4.5.1.7, RFC 4517 §4.2.26).
     */
    private function assertionIsValid(AttributeValueAssertionInterface $filter): bool
    {
        return $this->validAssertions->for($filter->getAttribute())->for($filter->getValue());
    }

    private function assertionValueIsValid(
        string $attribute,
        string $value,
    ): bool {
        if (!$this->syntaxResolver->conforms($attribute, $value)) {
            return false;
        }

        return $this->descriptorIsResolvable(
            $attribute,
            $value,
        );
    }

    /**
     * Only the descr form has to be recognized; a numeric OID names itself whether the schema defines it or not.
     */
    private function descriptorIsResolvable(
        string $attribute,
        string $value,
    ): bool {
        $equalityOid = $this->schema->getEqualityRuleOid(Attribute::normalizeName($attribute));

        if ($equalityOid !== MatchingRuleOid::OID_OBJECT_IDENTIFIER_MATCH) {
            return true;
        }

        return OidSyntaxValidator::isNumericForm($value)
            || $this->schema->oidFor($value) !== null;
    }

    /**
     * The SUBSTR rule the filter's type resolves to, or null when it declares none.
     */
    private function substringRuleOid(SubstringFilter $filter): ?string
    {
        $ruleOid = $this->substringRules->for($filter->getAttribute());

        return $ruleOid === false
            ? null
            : $ruleOid;
    }

    /**
     * Yes-or-no answers kept by attribute description or rule, and then by value.
     *
     * @param Closure(string, string): bool $check
     * @return BoundedMemo<string, BoundedMemo<string, bool>>
     */
    private static function answersByValue(Closure $check): BoundedMemo
    {
        return new BoundedMemo(
            self::MAX_REMEMBERED_NAMES,
            MemoScope::Process,
            static fn(string $name): BoundedMemo => new BoundedMemo(
                self::MAX_REMEMBERED_VALUES,
                MemoScope::Process,
                static fn(string $value): bool => $check(
                    $name,
                    $value,
                ),
            ),
        );
    }
}
