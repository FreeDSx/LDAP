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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Sql;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;

/**
 * Cross-platform sidecar SQL shared by every PdoSidecarDialectInterface implementation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoSidecarDialectTrait
{
    public function querySidecarDelete(): string
    {
        return <<<SQL
            DELETE FROM entry_attribute_values
            WHERE owner_entry_id = ?
        SQL;
    }

    public function querySidecarDeleteValues(int $count): string
    {
        $markers = SqlFilterUtility::markers(
            $count,
            '(?, ?)',
        );

        return <<<SQL
            DELETE FROM entry_attribute_values
            WHERE owner_entry_id = ?
              AND (attr_name_lower, value_lower) IN ($markers)
        SQL;
    }

    public function querySidecarInsert(int $count): string
    {
        $markers = SqlFilterUtility::markers(
            $count,
            '(?, ?, ?, ?)',
        );

        return <<<SQL
            INSERT INTO entry_attribute_values (owner_entry_id, attr_name_lower, value_lower, value_original)
            VALUES $markers
        SQL;
    }
}
