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
 * The full database-specific SQL a PdoStorage needs.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoDialectInterface extends PdoEntryDialectInterface, PdoJournalDialectInterface
{
    /**
     * The full schema (all tables) as a runnable SQL script.
     */
    public function schemaSql(): string;

    /**
     * The schema script split into individual executable statements.
     *
     * @return list<string>
     */
    public function schemaStatements(): array;

    /**
     * The statements of a named auxiliary schema (e.g. an optional substring index), for strategies to apply their own DDL.
     *
     * @return list<string>
     */
    public function schemaStatementsNamed(string $name): array;
}
