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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect;

/**
 * Standard SQL that should be cross-platform across the adapters.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoDialectTrait
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
            SELECT dn, attributes
            FROM entries
            WHERE lc_dn = ?
        SQL;
    }

    public function queryFetchAll(): string
    {
        return <<<SQL
            SELECT dn, attributes
            FROM entries
        SQL;
    }

    public function queryFetchChildren(): string
    {
        return <<<SQL
            SELECT dn, attributes
            FROM entries
            WHERE lc_parent_dn = ?
        SQL;
    }

    public function querySubtree(): string
    {
        return <<<SQL
            WITH RECURSIVE subtree AS (
                SELECT lc_dn, dn, attributes
                FROM entries
                WHERE lc_dn = ?
                UNION ALL
                SELECT e.lc_dn, e.dn, e.attributes
                FROM entries e
                INNER JOIN subtree s ON e.lc_parent_dn = s.lc_dn
            )
            SELECT dn, attributes FROM subtree
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

    public function queryDelete(): string
    {
        return <<<SQL
            DELETE FROM entries
            WHERE lc_dn = ?
        SQL;
    }
}
