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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Text;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\InvalidAttributeException;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\ApproximateFilter;
use FreeDSx\Ldap\Search\Filter\AttributeValueAssertionInterface;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\FilterAttributeInterface;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\LessThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Search\Filter\OrFilter;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedAttributeTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\AttributeFilterSupport;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContextInterface;

/**
 * Translates LDAP filters to SQL against the `entry_attribute_values` sidecar index.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait SqlFilterTranslatorTrait
{
    use DerivedAttributeTrait;

    private ?SubstringIndexInterface $substringIndex = null;

    private AttributeContextInterface $attributeContext;

    public function translate(FilterInterface $filter): ?SqlFilterResult
    {
        return $this->dispatch($filter);
    }

    /**
     * An item the type cannot answer is Undefined for every entry, whatever the attribute otherwise supports.
     */
    private function supportFor(FilterInterface $filter): AttributeFilterSupport
    {
        $conforms = !$filter instanceof AttributeValueAssertionInterface
            || $this->attributeContext->assertionValueConforms(
                $filter->getAttribute(),
                $filter->getValue(),
            );

        if (!$conforms) {
            return AttributeFilterSupport::NeverMatches;
        }

        // A substring item applies the type's SUBSTR rule, so a type declaring none cannot answer it.
        if ($filter instanceof SubstringFilter && !$this->attributeContext->hasSubstringRule($filter->getAttribute())) {
            return AttributeFilterSupport::NeverMatches;
        }

        $attribute = $filter instanceof FilterAttributeInterface
            ? $filter->getAttribute()
            : null;

        return $attribute === null
            ? AttributeFilterSupport::Exact
            : $this->attributeContext->filterSupport($attribute);
    }

    private function dispatch(FilterInterface $filter): ?SqlFilterResult
    {
        $support = $this->supportFor($filter);

        // Rows under this name alone are not the whole answer, so leave the item to the evaluator.
        if ($support === AttributeFilterSupport::NeedsEvaluator) {
            return null;
        }

        // Undefined for every entry, so on its own it selects nothing. It stays inexact because Undefined only
        // behaves like false until a negation is layered over it, and SQL has no third value to carry that.
        if ($support === AttributeFilterSupport::NeverMatches) {
            return new SqlFilterResult(
                '1 = 0',
                [],
                isExact: false,
            );
        }

        return match (true) {
            $filter instanceof AndFilter => $this->translateAnd($filter),
            $filter instanceof OrFilter => $this->translateOr($filter),
            $filter instanceof NotFilter => $this->translateNot($filter),
            $filter instanceof PresentFilter => $this->translatePresent($filter),
            $filter instanceof EqualityFilter => $this->translateEquality($filter),
            $filter instanceof ApproximateFilter => $this->translateApproximate($filter),
            $filter instanceof SubstringFilter => $this->translateSubstring($filter),
            $filter instanceof GreaterThanOrEqualFilter => $this->translateGte($filter),
            $filter instanceof LessThanOrEqualFilter => $this->translateLte($filter),
            default => null,
        };
    }

    /**
     * @param string $attribute Pre-validated; safe to embed in SQL.
     */
    abstract private function buildPresenceCheck(string $attribute): string;

    /**
     * @param string $attribute Pre-validated; safe to embed in SQL.
     */
    abstract private function buildValueExists(
        string $attribute,
        string $innerCondition,
    ): string;

    abstract private function valueAlias(): string;

    /**
     * Wraps an expression in a dialect-specific integer cast for numeric ordering comparisons.
     */
    abstract private function castToNumeric(string $expression): string;

    /**
     * A single leaf's sidecar sub-select WHERE body, mirroring what buildValueExists wraps, for the streaming fast path.
     */
    private function sidecarCondition(
        string $attribute,
        ?string $inner,
    ): string {
        $condition = "s.attr_name_lower = '$attribute'";

        return $inner !== null
            ? "$condition AND $inner"
            : $condition;
    }

    /**
     * Whether the item asserts on hasSubordinates, which is computed rather than stored so no sidecar row answers it.
     */
    private function isSubordinateCheck(string $attributeDescription): bool
    {
        return self::describesType(
            $attributeDescription,
            AttributeTypeOid::NAME_HAS_SUBORDINATES,
        );
    }

    /**
     * Correlated against the outer row, which every filtered query resolves against the unaliased entries table.
     */
    private function translateHasSubordinates(string $value): ?SqlFilterResult
    {
        $exists = <<<SQL
            EXISTS (
                SELECT 1
                FROM entries child
                WHERE child.lc_parent_dn = entries.lc_dn)
            SQL;

        // The syntax check upstream leaves only the two Boolean literals; anything else is left to the evaluator.
        $sql = match (strtoupper($value)) {
            'TRUE' => $exists,
            'FALSE' => "NOT $exists",
            default => null,
        };

        if ($sql === null) {
            return null;
        }

        return new SqlFilterResult(
            $sql,
            [],
            correlatedSql: $sql,
        );
    }

    private function translatePresent(PresentFilter $filter): ?SqlFilterResult
    {
        // Every entry has a subordinate state, so asserting its presence excludes nothing.
        if ($this->isSubordinateCheck($filter->getAttribute())) {
            return new SqlFilterResult(
                '1 = 1',
                [],
                correlatedSql: '1 = 1',
            );
        }

        $attribute = $this->validateAttribute($filter->getAttribute());

        return new SqlFilterResult(
            $this->buildPresenceCheck($attribute),
            [],
            isExact: !$this->attributeHasOption($filter->getAttribute()),
            sidecarCondition: $this->sidecarCondition(
                $attribute,
                null,
            ),
        );
    }

    private function translateEquality(EqualityFilter $filter): ?SqlFilterResult
    {
        if ($this->isSubordinateCheck($filter->getAttribute())) {
            return $this->translateHasSubordinates($filter->getValue());
        }

        $attribute = $this->validateAttribute($filter->getAttribute());

        $alias = $this->valueAlias();
        $value = $filter->getValue();

        // One object identifier has several spellings, so every one of them has to be offered to the index. Which
        // of them the stored value uses is left to the evaluator.
        $spellings = $this->attributeContext->oidSpellings(
            $filter->getAttribute(),
            $value,
        );

        if ($spellings !== null) {
            $condition = sprintf(
                '%s IN (%s)',
                $alias,
                SqlFilterUtility::markers(count($spellings)),
            );

            return new SqlFilterResult(
                $this->buildValueExists($attribute, $condition),
                array_map(
                    fn(string $spelling): string => $this->prepareMatchValue($spelling),
                    $spellings,
                ),
                isExact: false,
                sidecarCondition: $this->sidecarCondition(
                    $attribute,
                    $condition,
                ),
            );
        }

        // Stored text and the assertion can spell the same integer differently, so those compare as numbers. The
        // cast saturates at the platform integer, making it a superset the evaluator still has to check.
        if ($this->attributeContext->isIntegerOrdered($filter->getAttribute()) === true) {
            $condition = sprintf(
                '%s = %s',
                $this->castToNumeric($alias),
                $this->castToNumeric('?'),
            );

            return new SqlFilterResult(
                $this->buildValueExists($attribute, $condition),
                [$this->prepareMatchValue($value)],
                isExact: false,
                sidecarCondition: $this->sidecarCondition(
                    $attribute,
                    $condition,
                ),
            );
        }

        return new SqlFilterResult(
            $this->buildValueExists($attribute, "$alias = ?"),
            [$this->prepareMatchValue($value)],
            isExact: $this->isExactEquality($value)
                && $this->matchesCaseFolded($attribute)
                && !$this->attributeHasOption($filter->getAttribute()),
            sidecarCondition: $this->sidecarCondition(
                $attribute,
                "$alias = ?",
            ),
        );
    }

    private function translateApproximate(ApproximateFilter $filter): ?SqlFilterResult
    {
        $attribute = $this->validateAttribute($filter->getAttribute());

        $alias = $this->valueAlias();
        $value = $filter->getValue();

        // Implementation-defined (RFC 4511 §4.5.1.7.6); mirror FilterEvaluator's case-insensitive equality.
        return new SqlFilterResult(
            $this->buildValueExists($attribute, "$alias = ?"),
            [$this->prepareMatchValue($value)],
            isExact: $this->isExactEquality($value)
                && $this->matchesCaseFolded($attribute)
                && !$this->attributeHasOption($filter->getAttribute()),
            sidecarCondition: $this->sidecarCondition(
                $attribute,
                "$alias = ?",
            ),
        );
    }

    /**
     * Truncation preserves lexical GTE when query <= 255 chars: full >= query implies its prefix >= query.
     */
    private function translateGte(GreaterThanOrEqualFilter $filter): ?SqlFilterResult
    {
        return $this->translateOrdered(
            $filter->getAttribute(),
            $filter->getValue(),
            '>=',
            lexicalCanBeExact: true,
        );
    }

    /**
     * Lexical LTE under truncation admits false positives (stored value > 255 whose prefix equals query).
     */
    private function translateLte(LessThanOrEqualFilter $filter): ?SqlFilterResult
    {
        return $this->translateOrdered(
            $filter->getAttribute(),
            $filter->getValue(),
            '<=',
            lexicalCanBeExact: false,
        );
    }

    /**
     * Integer-ordered attributes narrow numerically (CAST, exact); others keep the lexical comparison, whose
     * exactness the caller bounds via $lexicalCanBeExact (GTE can be exact, LTE cannot under truncation).
     */
    private function translateOrdered(
        string $rawAttribute,
        string $value,
        string $operator,
        bool $lexicalCanBeExact,
    ): SqlFilterResult {
        $attribute = $this->validateAttribute($rawAttribute);
        $hasOption = $this->attributeHasOption($rawAttribute);

        if ($this->attributeContext->isIntegerOrdered($rawAttribute) === true) {
            $condition = sprintf(
                '%s %s %s',
                $this->castToNumeric($this->valueAlias()),
                $operator,
                $this->castToNumeric('?'),
            );

            return new SqlFilterResult(
                $this->buildValueExists($attribute, $condition),
                [$this->prepareMatchValue($value)],
                isExact: !$hasOption,
                sidecarCondition: $this->sidecarCondition($attribute, $condition),
            );
        }

        $condition = $this->valueAlias() . " $operator ?";

        return new SqlFilterResult(
            $this->buildValueExists($attribute, $condition),
            [$this->prepareMatchValue($value)],
            isExact: $lexicalCanBeExact
                && $this->isExactOrdered($value)
                && $this->matchesCaseFolded($attribute)
                && !$hasOption,
            sidecarCondition: $this->sidecarCondition(
                $attribute,
                $condition,
            ),
        );
    }

    private function translateSubstring(SubstringFilter $filter): ?SqlFilterResult
    {
        $attribute = $this->validateAttribute($filter->getAttribute());

        $startsWith = $filter->getStartsWith();
        $contains = $filter->getContains();
        $endsWith = $filter->getEndsWith();

        if ($startsWith === null && $contains === [] && $endsWith === null) {
            return null;
        }

        $indexed = $this->indexedSubstring(
            $attribute,
            $startsWith,
            $contains,
            $endsWith,
        );
        if ($indexed !== null) {
            return $indexed;
        }

        // Prefix-anchored LIKE is the only valid superset under truncation; other fragments fall back to presence + PHP re-eval.
        $alias = $this->valueAlias();

        if ($startsWith !== null) {
            // A fragment keeps its edge spaces, which a whole value would have trimmed.
            $prefix = SqlFilterUtility::normalizeFragment($startsWith);
            $inner = "$alias LIKE ? ESCAPE '!'";
            $sql = $this->buildValueExists(
                $attribute,
                $inner,
            );
            $params = [SqlFilterUtility::escape($prefix) . '%'];
            $sidecar = $this->sidecarCondition(
                $attribute,
                $inner,
            );
        } else {
            $sql = $this->buildPresenceCheck($attribute);
            $params = [];
            $sidecar = $this->sidecarCondition(
                $attribute,
                null,
            );
        }

        $fragmentsAreExact = $this->isExactSubstring(
            $startsWith,
            $contains,
            $endsWith,
        );

        $isExact = $fragmentsAreExact
            && $this->matchesCaseFolded($attribute)
            && !$this->attributeHasOption($filter->getAttribute());

        return new SqlFilterResult(
            $sql,
            $params,
            isExact: $isExact,
            sidecarCondition: $sidecar,
        );
    }

    /**
     * The substring index's candidate-narrowing predicate for an infix/suffix filter, or null when it does not apply.
     *
     * @param array<string> $contains
     */
    private function indexedSubstring(
        string $attribute,
        ?string $startsWith,
        array $contains,
        ?string $endsWith,
    ): ?SqlFilterResult {
        if ($startsWith !== null || $this->substringIndex === null) {
            return null;
        }

        return $this->substringIndex->buildSubstringPredicate(
            $attribute,
            $this->substringFragments(
                $contains,
                $endsWith,
            ),
        );
    }

    /**
     * @param array<string> $contains
     *
     * @return list<string>
     */
    private function substringFragments(
        array $contains,
        ?string $endsWith,
    ): array {
        $fragments = array_values($contains);

        if ($endsWith !== null) {
            $fragments[] = $endsWith;
        }

        return $fragments;
    }

    private function isExactEquality(string $value): bool
    {
        return Text::isAscii($value)
            && Text::isUtf8($value)
            && Text::lengthOf($value) <= SqlFilterUtility::MAX_INDEXED_VALUE_CHARS;
    }

    /**
     * Values are indexed and compared case-folded, so a case-sensitive attribute needs the caller to re-check.
     *
     * Unresolved attributes fall back to true, keeping the schema-less behaviour the in-process evaluator also has.
     */
    private function matchesCaseFolded(string $attribute): bool
    {
        return $this->attributeContext->isCaseInsensitive($attribute) ?? true;
    }

    /**
     * ASCII non-digit within truncation; digit-only values compare numerically in PHP but lexically in SQL.
     */
    private function isExactOrdered(string $value): bool
    {
        return Text::isAscii($value)
            && !ctype_digit($value)
            && Text::isUtf8($value)
            && Text::lengthOf($value) <= SqlFilterUtility::MAX_INDEXED_VALUE_CHARS;
    }

    /**
     * @param array<string> $contains
     */
    private function isExactSubstring(
        ?string $startsWith,
        array $contains,
        ?string $endsWith,
    ): bool {
        if ($startsWith === null) {
            return false;
        }

        if ($contains !== [] || $endsWith !== null) {
            return false;
        }

        return Text::isAscii($startsWith)
            && Text::isUtf8($startsWith)
            && Text::lengthOf($startsWith) <= SqlFilterUtility::MAX_INDEXED_VALUE_CHARS;
    }

    /**
     * Prepared the same way the sidecar's value_lower was written, so SQL and the evaluator agree.
     */
    private function prepareMatchValue(string $value): string
    {
        return SqlFilterUtility::normalize($value);
    }

    private function translateAnd(AndFilter $filter): ?SqlFilterResult
    {
        $parts = [];
        $correlatedParts = [];
        $params = [];
        $drivableLeaves = [];
        $hasUntranslatable = false;
        $allCorrelatable = true;

        foreach ($filter->get() as $child) {
            $result = $this->dispatch($child);
            if ($result === null) {
                $hasUntranslatable = true;
                continue;
            }
            if (!$result->isExact) {
                $hasUntranslatable = true;
            }
            $parts[] = '(' . $result->sql . ')';
            array_push($params, ...$result->params);
            array_push($drivableLeaves, ...$this->drivableLeavesOf($result));

            if ($result->correlatedSql !== null) {
                $correlatedParts[] = '(' . $result->correlatedSql . ')';
            } else {
                $allCorrelatable = false;
            }
        }

        if ($parts === []) {
            return null;
        }

        return new SqlFilterResult(
            implode(' AND ', $parts),
            $params,
            isExact: !$hasUntranslatable,
            drivableLeaves: $drivableLeaves,
            correlatedSql: $allCorrelatable
                ? implode(' AND ', $correlatedParts)
                : null,
        );
    }

    /**
     * A child's contribution to an AND's drivable-leaf set: itself if a single leaf, or its own leaves if a nested AND.
     *
     * @return list<SidecarLeaf>
     */
    private function drivableLeavesOf(SqlFilterResult $result): array
    {
        if ($result->sidecarCondition !== null) {
            return [
                new SidecarLeaf(
                    $result->sidecarCondition,
                    $result->params,
                ),
            ];
        }

        return $result->drivableLeaves;
    }

    private function translateOr(OrFilter $filter): ?SqlFilterResult
    {
        $parts = [];
        $correlatedParts = [];
        $params = [];
        $hasInexact = false;
        $allCorrelatable = true;

        foreach ($filter->get() as $child) {
            $result = $this->dispatch($child);
            if ($result === null) {
                return null;
            }
            if (!$result->isExact) {
                $hasInexact = true;
            }
            $parts[] = '(' . $result->sql . ')';
            array_push($params, ...$result->params);

            if ($result->correlatedSql !== null) {
                $correlatedParts[] = '(' . $result->correlatedSql . ')';
            } else {
                $allCorrelatable = false;
            }
        }

        if ($parts === []) {
            return null;
        }

        return new SqlFilterResult(
            implode(' OR ', $parts),
            $params,
            isExact: !$hasInexact,
            correlatedSql: $allCorrelatable
                ? implode(' OR ', $correlatedParts)
                : null,
        );
    }

    private function translateNot(NotFilter $filter): ?SqlFilterResult
    {
        $inner = $filter->get();
        $result = $this->dispatch($inner);

        if ($result === null) {
            return null;
        }

        // An assertion the schema defines is false when the entry lacks the attribute, so negating it legitimately
        // matches those rows and plain `NOT (...)` is precise. Types the schema does not define never reach here;
        // dispatch() has already answered them.
        return new SqlFilterResult(
            'NOT (' . $result->sql . ')',
            $result->params,
            isExact: $result->isExact,
            correlatedSql: $result->correlatedSql !== null
                ? 'NOT (' . $result->correlatedSql . ')'
                : null,
        );
    }

    /**
     * The lowercased attribute type an identifier may carry, once the RFC 4512 2.5 grammar admits it.
     *
     * @throws InvalidAttributeException
     */
    private function validateAttribute(string $attribute): string
    {
        if (!Attribute::isValidDescription($attribute)) {
            throw new InvalidAttributeException(sprintf(
                'Attribute description "%s" is not a valid RFC 4512 attribute description.',
                $attribute,
            ));
        }

        return explode(
            ';',
            strtolower($attribute),
            2,
        )[0];
    }

    /**
     * An option-bearing filter is a SQL superset, since the base-keyed sidecar cannot distinguish the subtype.
     */
    private function attributeHasOption(string $attribute): bool
    {
        return str_contains($attribute, ';');
    }
}
