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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support;

use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\MatchingRuleOid;
use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorInterface;
use FreeDSx\Ldap\Schema\Schema;

/**
 * Sorts a list of entries in-place by an ordered list of SortKeys.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SortKeyComparator
{
    public function __construct(private readonly ?Schema $schema = null) {}

    /**
     * Returns a new sorted array.
     *
     * @param list<Entry> $entries
     * @param SortKey[] $sortKeys
     * @return list<Entry>
     */
    public function sort(
        array $entries,
        array $sortKeys,
    ): array {
        usort(
            $entries,
            fn(Entry $a, Entry $b): int => $this->compare(
                $a,
                $b,
                $sortKeys,
            ),
        );

        return $entries;
    }

    /**
     * @param SortKey[] $sortKeys
     */
    private function compare(
        Entry $a,
        Entry $b,
        array $sortKeys,
    ): int {
        foreach ($sortKeys as $sortKey) {
            $result = $this->compareByKey(
                $a,
                $b,
                $sortKey,
            );

            if ($result !== 0) {
                return $result;
            }
        }

        return 0;
    }

    private function compareByKey(
        Entry $a,
        Entry $b,
        SortKey $sortKey,
    ): int {
        $cmp = $this->rawCompare(
            $this->minValue(
                $a,
                $sortKey->getAttribute(),
            ),
            $this->minValue(
                $b,
                $sortKey->getAttribute(),
            ),
            $this->orderingFor($sortKey),
        );

        return $sortKey->getUseReverseOrder() ? -$cmp : $cmp;
    }

    /**
     * The rule the key asks for, else the one its attribute declares; null when neither resolves.
     */
    private function orderingFor(SortKey $sortKey): ?MatchingRuleComparatorInterface
    {
        $schema = $this->schema;

        if ($schema === null) {
            return null;
        }

        $rule = $sortKey->getOrderingRule();

        if ($rule !== null) {
            return $schema->getComparator($rule);
        }

        $orderingOid = $schema->getOrderingRuleOid($sortKey->getAttribute());

        if ($orderingOid !== null) {
            return $schema->getComparator($orderingOid);
        }

        // A type can order numerically through its syntax alone, without naming an ordering rule.
        return $schema->isIntegerOrdered($sortKey->getAttribute()) === true
            ? $schema->getComparator(MatchingRuleOid::OID_INTEGER_ORDERING_MATCH)
            : null;
    }

    /**
     * Compares two values treating NULL (a missing attribute) as the largest value, per RFC 2891 §2.2.
     */
    private function rawCompare(
        ?string $aValue,
        ?string $bValue,
        ?MatchingRuleComparatorInterface $ordering,
    ): int {
        if ($aValue === null && $bValue === null) {
            return 0;
        }

        if ($aValue === null) {
            return 1;
        }

        if ($bValue === null) {
            return -1;
        }

        if ($ordering !== null) {
            return $ordering->compare(
                $aValue,
                $bValue,
            );
        }

        return strcasecmp(
            $aValue,
            $bValue,
        );
    }

    /**
     * Returns the case-insensitive minimum value, consistent with the SQL backend's MIN(value_lower).
     * Null when the attribute is absent or empty.
     */
    private function minValue(
        Entry $entry,
        string $attribute,
    ): ?string {
        $attr = $entry->get($attribute);

        if ($attr === null) {
            return null;
        }

        $values = $attr->getValues();

        if ($values === []) {
            return null;
        }

        return array_reduce(
            $values,
            self::caseInsensitiveMin(...),
        );
    }

    private static function caseInsensitiveMin(
        ?string $min,
        string $value,
    ): string {
        return $min === null || strcasecmp($value, $min) < 0
            ? $value
            : $min;
    }
}
