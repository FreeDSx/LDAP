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

use FreeDSx\Ldap\Server\Backend\Storage\Exception\InvalidAttributeException;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\ApproximateFilter;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\LessThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Search\Filter\OrFilter;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;

/**
 * Reusable LDAP-filter-to-SQL translator; concrete classes supply buildPresenceCheck() and buildValueExists().
 *
 * Composition rules: AND keeps translatable children, OR requires every child to translate, NOT honors RFC 4511 §4.5.1.7,
 * MatchingRuleFilter is never translated.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait SqlFilterTranslatorTrait
{
    /**
     * SQL fragment testing whether the attribute key is present.
     *
     * @param string $attribute Pre-validated and safe to embed in SQL.
     */
    abstract protected function buildPresenceCheck(string $attribute): string;

    /**
     * Wraps $innerCondition so it is evaluated per attribute value, referencing the current value via {@see valueAlias()}.
     *
     * @param string $attribute Pre-validated and safe to embed in SQL.
     */
    abstract protected function buildValueExists(
        string $attribute,
        string $innerCondition,
    ): string;

    /**
     * Returns the column alias used by the value-iteration function.
     */
    abstract protected function valueAlias(): string;

    public function translate(FilterInterface $filter): ?SqlFilterResult
    {
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

    private function translatePresent(PresentFilter $filter): ?SqlFilterResult
    {
        $attribute = $this->validateAttribute($filter->getAttribute());

        return new SqlFilterResult(
            $this->buildPresenceCheck($attribute),
            [],
        );
    }

    private function translateEquality(EqualityFilter $filter): ?SqlFilterResult
    {
        $attribute = $this->validateAttribute($filter->getAttribute());

        $alias = $this->valueAlias();
        $value = $filter->getValue();

        return new SqlFilterResult(
            $this->buildValueExists($attribute, "lower($alias) = lower(?)"),
            [$value],
            isExact: SqlFilterUtility::isAscii($value),
            referencedAttributes: [$attribute],
        );
    }

    private function translateApproximate(ApproximateFilter $filter): ?SqlFilterResult
    {
        $attribute = $this->validateAttribute($filter->getAttribute());

        $alias = $this->valueAlias();
        $value = $filter->getValue();

        // Approximate matching is implementation-defined (RFC 4511 §4.5.1.7.6).
        // Both SQL and PHP implementations pick case-insensitive equality, so
        // for ASCII values the result is exact and PHP re-eval can be skipped.
        return new SqlFilterResult(
            $this->buildValueExists($attribute, "lower($alias) = lower(?)"),
            [$value],
            isExact: SqlFilterUtility::isAscii($value),
            referencedAttributes: [$attribute],
        );
    }

    private function translateGte(GreaterThanOrEqualFilter $filter): ?SqlFilterResult
    {
        $attribute = $this->validateAttribute($filter->getAttribute());

        $alias = $this->valueAlias();
        $value = $filter->getValue();

        return new SqlFilterResult(
            $this->buildValueExists($attribute, "lower($alias) >= lower(?)"),
            [$value],
            isExact: $this->isOrderedCompareExact($value),
            referencedAttributes: [$attribute],
        );
    }

    private function translateLte(LessThanOrEqualFilter $filter): ?SqlFilterResult
    {
        $attribute = $this->validateAttribute($filter->getAttribute());

        $alias = $this->valueAlias();
        $value = $filter->getValue();

        return new SqlFilterResult(
            $this->buildValueExists($attribute, "lower($alias) <= lower(?)"),
            [$value],
            isExact: $this->isOrderedCompareExact($value),
            referencedAttributes: [$attribute],
        );
    }

    /**
     * Exact only for ASCII non-digit values; PHP compareOrdered int-compares when both operands are digits, SQL does not.
     */
    private function isOrderedCompareExact(string $value): bool
    {
        return SqlFilterUtility::isAscii($value)
            && !ctype_digit($value);
    }

    private function translateSubstring(SubstringFilter $filter): ?SqlFilterResult
    {
        $attribute = $this->validateAttribute($filter->getAttribute());

        [$conditions, $params] = $this->buildSubstringParts($filter);

        if ($conditions === []) {
            return null;
        }

        // LDAP substring ordering (RFC 4511 §4.5.1.7.2) requires each fragment
        // to appear strictly after the previous one. Independent AND'd LIKE
        // clauses cannot preserve that ordering, so we can only mark the result
        // exact when each part is independently anchored:
        //   - startsWith only, endsWith only, or both without contains
        //   - a single contains without startsWith/endsWith
        // Any contains + anchor combination (or 2+ contains) needs PHP re-eval.
        $containsCount = count($filter->getContains());
        $hasAnchor = $filter->getStartsWith() !== null
            || $filter->getEndsWith() !== null;

        $isExact = $containsCount < 2
            && !($containsCount > 0 && $hasAnchor)
            && SqlFilterUtility::isAscii((string) $filter->getStartsWith())
            && SqlFilterUtility::isAscii((string) $filter->getEndsWith())
            && $this->areAllAscii($filter->getContains());

        return new SqlFilterResult(
            $this->buildValueExists($attribute, implode(' AND ', $conditions)),
            $params,
            isExact: $isExact,
            referencedAttributes: [$attribute],
        );
    }

    /**
     * @param array<int|string, string> $values
     */
    private function areAllAscii(array $values): bool
    {
        foreach ($values as $value) {
            if (!SqlFilterUtility::isAscii($value)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return array{list<string>, list<string>}
     */
    private function buildSubstringParts(SubstringFilter $filter): array
    {
        $conditions = [];
        $params = [];
        $alias = $this->valueAlias();
        $likeClause = "lower($alias) LIKE lower(?) ESCAPE '!'";

        if ($filter->getStartsWith() !== null) {
            $conditions[] = $likeClause;
            $params[] = SqlFilterUtility::escape($filter->getStartsWith()) . '%';
        }

        foreach ($filter->getContains() as $contains) {
            $conditions[] = $likeClause;
            $params[] = '%' . SqlFilterUtility::escape($contains) . '%';
        }

        if ($filter->getEndsWith() !== null) {
            $conditions[] = $likeClause;
            $params[] = '%' . SqlFilterUtility::escape($filter->getEndsWith());
        }

        return [$conditions, $params];
    }

    private function translateAnd(AndFilter $filter): ?SqlFilterResult
    {
        $parts = [];
        $params = [];
        $hasUntranslatable = false;

        foreach ($filter->get() as $child) {
            $result = $this->translate($child);
            if ($result === null) {
                $hasUntranslatable = true;
                continue;
            }
            if (!$result->isExact) {
                $hasUntranslatable = true;
            }
            $parts[] = '(' . $result->sql . ')';
            array_push($params, ...$result->params);
        }

        if ($parts === []) {
            return null;
        }

        return new SqlFilterResult(
            implode(' AND ', $parts),
            $params,
            isExact: !$hasUntranslatable,
        );
    }

    private function translateOr(OrFilter $filter): ?SqlFilterResult
    {
        $parts = [];
        $params = [];
        $hasInexact = false;

        foreach ($filter->get() as $child) {
            $result = $this->translate($child);
            if ($result === null) {
                return null;
            }
            if (!$result->isExact) {
                $hasInexact = true;
            }
            $parts[] = '(' . $result->sql . ')';
            array_push($params, ...$result->params);
        }

        if ($parts === []) {
            return null;
        }

        return new SqlFilterResult(
            implode(' OR ', $parts),
            $params,
            isExact: !$hasInexact,
        );
    }

    private function translateNot(NotFilter $filter): ?SqlFilterResult
    {
        $inner = $filter->get();
        $result = $this->translate($inner);

        if ($result === null) {
            return null;
        }

        // NOT(present) is the one negation that legitimately matches absent
        // attributes, so no presence guard is needed.
        if ($inner instanceof PresentFilter) {
            return new SqlFilterResult(
                'NOT (' . $result->sql . ')',
                $result->params,
                isExact: $result->isExact,
            );
        }

        // RFC 4511 §4.5.1.7: NOT(undefined) = undefined. SQL `NOT EXISTS(...)`
        // returns TRUE for rows missing the attribute, so for value-bearing
        // simple filters (those that populated referencedAttributes) we AND
        // in a presence guard so missing-attribute rows are excluded.
        if ($result->referencedAttributes !== []) {
            $guards = array_map(
                fn (string $attribute): string => $this->buildPresenceCheck($attribute),
                array_values(array_unique($result->referencedAttributes)),
            );

            return new SqlFilterResult(
                '(NOT (' . $result->sql . ') AND ' . implode(' AND ', $guards) . ')',
                $result->params,
                isExact: $result->isExact,
            );
        }

        // Composite inner (AND/OR/NOT): tracking three-valued logic precisely
        // through SQL composition is fragile. The plain `NOT (...)` SQL is a
        // SUPERSET of the correct LDAP result for missing-attribute rows, so
        // marking it inexact lets the PHP FilterEvaluator strip false positives.
        return new SqlFilterResult(
            'NOT (' . $result->sql . ')',
            $result->params,
            isExact: false,
        );
    }

    /**
     * Validates an LDAP attribute description against the RFC 4512 syntax:
     *
     *   attributedescription = attributetype options
     *   attributetype        = oid
     *   oid                  = descr / numericoid
     *   descr                = keystring (e.g. "cn", "userCertificate")
     *   numericoid           = number 1*( DOT number ) (e.g. "2.5.4.3")
     *   options              = *( ";" option )
     *   option               = 1*keychar
     *
     * @throws InvalidAttributeException
     */
    private function validateAttribute(string $attribute): string
    {
        $lower = strtolower($attribute);

        if (preg_match('/^([a-z][a-z0-9-]*|\d+(\.\d+)+)(;[a-z0-9-]+)*$/', $lower) !== 1) {
            throw new InvalidAttributeException(sprintf(
                'Attribute description "%s" is not a valid RFC 4512 attribute description.',
                $attribute
            ));
        }

        return explode(
            ';',
            $lower,
            2,
        )[0];
    }
}
