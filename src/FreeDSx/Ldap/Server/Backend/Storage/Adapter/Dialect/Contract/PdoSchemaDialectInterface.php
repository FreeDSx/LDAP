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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract;

/**
 * Database-specific schema DDL.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoSchemaDialectInterface
{
    /**
     * The baseline schema as one script.
     */
    public function schemaSql(): string;

    /**
     * The baseline schema as separate statements.
     *
     * @return list<string>
     */
    public function schemaStatements(): array;

    /**
     * The statements of a named auxiliary schema.
     *
     * @return list<string>
     */
    public function schemaStatementsNamed(string $name): array;
}
