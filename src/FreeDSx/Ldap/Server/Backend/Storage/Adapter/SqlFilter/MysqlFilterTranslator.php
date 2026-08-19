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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContextInterface;

/**
 * MySQL/MariaDB SQL WHERE translator for LDAP filters; targets the `entry_attribute_values` sidecar index.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class MysqlFilterTranslator implements FilterTranslatorInterface
{
    use SqlFilterTranslatorTrait;

    public function __construct(
        AttributeContextInterface $attributeContext,
        ?SubstringIndexInterface $substringIndex = null,
    ) {
        $this->attributeContext = $attributeContext;
        $this->substringIndex = $substringIndex;
    }

    private function buildPresenceCheck(string $attribute): string
    {
        return <<<SQL
            lc_dn IN (SELECT s.entry_lc_dn FROM entry_attribute_values s
                WHERE s.attr_name_lower = '$attribute')
            SQL;
    }

    private function buildValueExists(
        string $attribute,
        string $innerCondition,
    ): string {
        return <<<SQL
            lc_dn IN (SELECT s.entry_lc_dn FROM entry_attribute_values s
                WHERE s.attr_name_lower = '$attribute' AND $innerCondition)
            SQL;
    }

    private function valueAlias(): string
    {
        return 's.value_lower';
    }

    private function castToNumeric(string $expression): string
    {
        return "CAST($expression AS SIGNED)";
    }
}
