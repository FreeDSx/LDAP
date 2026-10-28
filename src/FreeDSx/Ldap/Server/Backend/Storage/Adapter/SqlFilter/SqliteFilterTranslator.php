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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\NoSubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContextInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeIndexForms;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;

/**
 * SQLite SQL WHERE translator for LDAP filters; targets the `entry_attribute_values` sidecar index.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SqliteFilterTranslator implements FilterTranslatorInterface
{
    use SqlFilterTranslatorTrait;

    public function __construct(
        AttributeContextInterface $attributeContext,
        AttributeIndexForms $indexForms,
        LinkedAttributes $linked,
        SubstringIndexInterface $substringIndex = new NoSubstringIndex(),
    ) {
        $this->attributeContext = $attributeContext;
        $this->indexForms = $indexForms;
        $this->linked = $linked;
        $this->substringIndex = $substringIndex;
    }

    private function buildPresenceCheck(string $attribute): string
    {
        return <<<SQL
            entry_id IN (SELECT s.owner_entry_id FROM entry_attribute_values s
                WHERE s.attr_name_lower = '$attribute')
            SQL;
    }

    private function buildValueExists(
        string $attribute,
        string $innerCondition,
    ): string {
        return <<<SQL
            entry_id IN (SELECT s.owner_entry_id FROM entry_attribute_values s
                WHERE s.attr_name_lower = '$attribute' AND $innerCondition)
            SQL;
    }

    private function valueAlias(): string
    {
        return 's.value_lower';
    }

    private function castToNumeric(string $expression): string
    {
        return "CAST($expression AS INTEGER)";
    }

    /**
     * SQLite saturates an integer cast at the signed 64-bit limits.
     */
    private function numericCastBound(): string
    {
        return '9223372036854775807';
    }

    /**
     * A byte range seeks the BINARY index on the already folded value, where SQLite's case-insensitive LIKE cannot.
     */
    private function prefixCondition(string $alias): string
    {
        return "$alias >= ? AND $alias < ?";
    }

    /**
     * @return list<string>
     */
    private function prefixParams(string $prefix): array
    {
        return [
            $prefix,
            SqlFilterUtility::prefixUpperBound($prefix),
        ];
    }
}
