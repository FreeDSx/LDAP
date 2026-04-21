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

use PDO;

/**
 * Standard SQL that should be cross-platform across the adapters.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoDialectTrait
{
    public function beginTransaction(PDO $pdo): void
    {
        $pdo->beginTransaction();
    }

    public function commit(PDO $pdo): void
    {
        $pdo->commit();
    }

    public function rollBack(PDO $pdo): void
    {
        $pdo->rollBack();
    }

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

    public function querySidecarDelete(): string
    {
        return <<<SQL
            DELETE FROM entry_attribute_values
            WHERE entry_lc_dn = ?
        SQL;
    }

    public function querySidecarInsertPrefix(): string
    {
        return 'INSERT INTO entry_attribute_values (entry_lc_dn, attr_name_lower, value_lower, value_original) VALUES ';
    }
}
