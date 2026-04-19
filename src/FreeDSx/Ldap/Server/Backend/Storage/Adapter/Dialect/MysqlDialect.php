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
 * MySQL/MariaDB SQL for PdoStorage; requires MySQL 8.0+ or MariaDB 10.6+.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class MysqlDialect implements PdoDialectInterface
{
    use PdoDialectTrait;

    /**
     * DN columns are 768 chars — the maximum that still fits an InnoDB index.
     *
     * @TODO How to handle indexing on attributes?
     */
    public function ddlCreateTable(): string
    {
        return <<<SQL
            CREATE TABLE IF NOT EXISTS entries (
                lc_dn         VARCHAR(768) NOT NULL,
                dn            VARCHAR(768) NOT NULL,
                lc_parent_dn  VARCHAR(768) NOT NULL DEFAULT '',
                attributes    JSON NOT NULL,
                PRIMARY KEY (lc_dn),
                INDEX idx_lc_parent_dn (lc_parent_dn)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        SQL;
    }

    /**
     * Null: the index is defined inline in ddlCreateTable().
     */
    public function ddlCreateIndex(): ?string
    {
        return null;
    }

    /**
     * @todo Replace VALUES() (deprecated in MySQL 8.0.20, removed in 9.0) with row alias syntax once MariaDB supports it.
     */
    public function queryUpsert(): string
    {
        return <<<SQL
            INSERT INTO entries (lc_dn, dn, lc_parent_dn, attributes)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                dn = VALUES(dn),
                lc_parent_dn = VALUES(lc_parent_dn),
                attributes = VALUES(attributes)
        SQL;
    }

    public function maxDnLength(): int
    {
        return 768;
    }
}
