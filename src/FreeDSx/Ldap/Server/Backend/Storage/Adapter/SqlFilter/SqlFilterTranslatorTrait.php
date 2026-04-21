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
 * Translates LDAP filters to SQL against the `entry_attribute_values` sidecar index.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait SqlFilterTranslatorTrait
{
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
            $this->buildValueExists($attribute, "$alias = ?"),
            [$this->prepareMatchValue($value)],
            isExact: $this->isExactEquality($value),
            referencedAttributes: [$attribute],
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
            isExact: $this->isExactEquality($value),
            referencedAttributes: [$attribute],
        );
    }

    private function translateGte(GreaterThanOrEqualFilter $filter): ?SqlFilterResult
    {
        $attribute = $this->validateAttribute($filter->getAttribute());

        $alias = $this->valueAlias();
        $value = $filter->getValue();

        // Truncation preserves GTE when query <= 255 chars: full >= query implies its prefix >= query.
        return new SqlFilterResult(
            $this->buildValueExists($attribute, "$alias >= ?"),
            [$this->prepareMatchValue($value)],
            isExact: $this->isExactOrdered($value),
            referencedAttributes: [$attribute],
        );
    }

    private function translateLte(LessThanOrEqualFilter $filter): ?SqlFilterResult
    {
        $attribute = $this->validateAttribute($filter->getAttribute());

        $alias = $this->valueAlias();
        $value = $filter->getValue();

        // LTE under truncation admits false positives (stored value > 255 whose prefix equals query); always inexact.
        return new SqlFilterResult(
            $this->buildValueExists($attribute, "$alias <= ?"),
            [$this->prepareMatchValue($value)],
            isExact: false,
            referencedAttributes: [$attribute],
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

        // Prefix-anchored LIKE is the only valid superset under truncation; other fragments fall back to presence + PHP re-eval.
        $alias = $this->valueAlias();

        if ($startsWith !== null) {
            $prefix = $this->prepareMatchValue($startsWith);
            $sql = $this->buildValueExists(
                $attribute,
                "$alias LIKE ? ESCAPE '!'",
            );
            $params = [SqlFilterUtility::escape($prefix) . '%'];
        } else {
            $sql = $this->buildPresenceCheck($attribute);
            $params = [];
        }

        $isExact = $this->isExactSubstring(
            $startsWith,
            $contains,
            $endsWith,
        );

        return new SqlFilterResult(
            $sql,
            $params,
            isExact: $isExact,
            referencedAttributes: [$attribute],
        );
    }

    private function isExactEquality(string $value): bool
    {
        return SqlFilterUtility::isAscii($value)
            && mb_check_encoding($value, 'UTF-8')
            && mb_strlen($value, 'UTF-8') <= SqlFilterUtility::MAX_INDEXED_VALUE_CHARS;
    }

    /**
     * ASCII non-digit within truncation; digit-only values compare numerically in PHP but lexically in SQL.
     */
    private function isExactOrdered(string $value): bool
    {
        return SqlFilterUtility::isAscii($value)
            && !ctype_digit($value)
            && mb_check_encoding($value, 'UTF-8')
            && mb_strlen($value, 'UTF-8') <= SqlFilterUtility::MAX_INDEXED_VALUE_CHARS;
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

        return SqlFilterUtility::isAscii($startsWith)
            && mb_check_encoding($startsWith, 'UTF-8')
            && mb_strlen($startsWith, 'UTF-8') <= SqlFilterUtility::MAX_INDEXED_VALUE_CHARS;
    }

    /**
     * Pre-lower + truncate to match sidecar's value_lower; non-UTF-8 returns '' (matches binary-syntax rows only).
     */
    private function prepareMatchValue(string $value): string
    {
        if (!mb_check_encoding($value, 'UTF-8')) {
            return '';
        }

        return mb_substr(
            mb_strtolower($value, 'UTF-8'),
            0,
            SqlFilterUtility::MAX_INDEXED_VALUE_CHARS,
            'UTF-8',
        );
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
