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

namespace FreeDSx\Ldap\Server\Backend\Storage\Schema;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Schema\Definition\MatchingRuleOid;
use FreeDSx\Ldap\Schema\Matching\EqualityComparatorResolver;
use FreeDSx\Ldap\Schema\Matching\IndexableComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorInterface;
use FreeDSx\Ldap\Schema\Schema;

/**
 * The forms a store must key an attribute's values by for its index to answer the rule the evaluator applies.
 *
 * Null means the rule cannot be represented, which leaves the assertion to be evaluated in PHP instead.
 *
 * @internal used by the PDO index writer and filter translators
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class AttributeIndexForms
{
    /**
     * Substring rules matching a fragment contiguously inside a plainly lowercased value.
     */
    private const CONTIGUOUS_SUBSTRING_OIDS = [
        MatchingRuleOid::OID_CASE_IGNORE_SUBSTRINGS_MATCH,
        MatchingRuleOid::OID_CASE_EXACT_SUBSTRINGS_MATCH,
        MatchingRuleOid::OID_CASE_IGNORE_IA5_SUBSTRINGS_MATCH,
        MatchingRuleOid::OID_CASE_IGNORE_LIST_SUBSTRINGS_MATCH,
    ];

    public function __construct(
        private Schema $schema,
        private EqualityComparatorResolver $equality,
    ) {}

    /**
     * The stored form of a value, and the form an equality assertion has to be prepared into to meet it.
     */
    public function key(
        string $attribute,
        string $value,
    ): ?string {
        $comparator = $this->equality->for($attribute);

        return $comparator instanceof IndexableComparatorInterface
            ? $comparator->indexKey($value)
            : null;
    }

    /**
     * One column holds one preparation, so an ordering comparison only reaches it when the same rule owns both.
     */
    public function orderingKey(
        string $attribute,
        string $value,
    ): ?string {
        $ordering = $this->orderingComparator($attribute);

        return $ordering !== null && $ordering === $this->equality->for($attribute)
            ? $this->key($attribute, $value)
            : null;
    }

    /**
     * A fragment has to land in the form the equality rule wrote, so a differing SUBSTR rule cannot use the column.
     */
    public function fragment(
        string $attribute,
        string $fragment,
    ): ?string {
        $substring = $this->substringComparator($attribute);

        if ($substring === null || $substring !== $this->equality->for($attribute)) {
            return null;
        }

        return $substring instanceof IndexableComparatorInterface
            ? $substring->indexFragment($fragment)
            : null;
    }

    /**
     * A substring index storing plainly lowercased values narrows only the rules that match over that same form.
     */
    public function substringIndexApplies(string $attribute): bool
    {
        $ruleOid = $this->schema->getSubstringRuleOid(Attribute::normalizeName($attribute));

        return $ruleOid !== null
            && in_array(
                $ruleOid,
                self::CONTIGUOUS_SUBSTRING_OIDS,
                true,
            );
    }

    /**
     * A type with no rule of its own or from its supertypes has no ordering the stored key could honour.
     */
    private function orderingComparator(string $attribute): ?MatchingRuleComparatorInterface
    {
        $orderingOid = $this->schema->getOrderingRuleOid(Attribute::normalizeName($attribute));

        return $orderingOid === null
            ? null
            : $this->schema->getComparator($orderingOid);
    }

    private function substringComparator(string $attribute): ?MatchingRuleComparatorInterface
    {
        $ruleOid = $this->schema->getSubstringRuleOid(Attribute::normalizeName($attribute));

        return $ruleOid === null
            ? null
            : $this->schema->getComparator($ruleOid);
    }
}
