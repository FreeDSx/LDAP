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

/**
 * MySQL/MariaDB SQL WHERE translator for LDAP filters; targets the `entry_attribute_values` sidecar index.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class MysqlFilterTranslator implements FilterTranslatorInterface
{
    use SqlFilterTranslatorTrait;

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
}
