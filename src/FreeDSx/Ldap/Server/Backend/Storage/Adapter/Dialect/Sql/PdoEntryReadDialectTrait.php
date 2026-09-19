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

/**
 * Cross-platform entry read SQL shared by every PdoEntryReadDialectInterface implementation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoEntryReadDialectTrait
{
    public function queryExists(): string
    {
        return <<<SQL
            SELECT 1
            FROM entries
            WHERE lc_dn = ?
            LIMIT 1
        SQL;
    }

    public function queryFetchEntry(): string
    {
        return <<<SQL
            SELECT entry_id, dn, attributes
            FROM entries
            WHERE lc_dn = ?
        SQL;
    }

    public function queryHasChildren(): string
    {
        return <<<SQL
            SELECT 1
            FROM entries
            WHERE lc_parent_dn = ?
            LIMIT 1
        SQL;
    }

    public function queryNamingContexts(): string
    {
        return <<<SQL
            SELECT dn
            FROM entries
            WHERE lc_parent_dn = ''
               OR lc_parent_dn NOT IN (SELECT lc_dn FROM entries)
        SQL;
    }
}
