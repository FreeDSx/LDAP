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
 * MySQL/MariaDB SQL WHERE translator for LDAP filters; requires MySQL 8.0+ or MariaDB 10.6+.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class MysqlFilterTranslator implements FilterTranslatorInterface
{
    use SqlFilterTranslatorTrait;

    protected function buildPresenceCheck(string $attribute): string
    {
        return "JSON_CONTAINS_PATH(attributes, 'one', '$.\"{$attribute}\"')";
    }

    protected function buildValueExists(
        string $attribute,
        string $innerCondition,
    ): string {
        // NO_SEMIJOIN is required: MySQL 8.0 silently rewrites the correlated JSON_TABLE
        // subquery into an unconditional hash join that loses the outer `attributes` reference,
        // producing zero rows for every filter.
        return <<<SQL
            EXISTS (
                SELECT /*+ NO_SEMIJOIN() */ 1
                FROM JSON_TABLE(
                    attributes,
                    '$."{$attribute}".values[*]' COLUMNS (val TEXT PATH '$')
                ) AS _jt
                WHERE $innerCondition
            )
        SQL;
    }

    protected function valueAlias(): string
    {
        return 'val';
    }
}
