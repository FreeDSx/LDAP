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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\NoSubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use PDO;

/**
 * The PDO storage schema for one dialect and substring index, to apply to a database or export as SQL.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class PdoSchema
{
    /**
     * The current schema revision shipped in resources/pdo-schema.
     */
    public const VERSION = 1;

    public function __construct(
        private PdoDialectInterface $dialect,
        private SubstringIndexInterface $substringIndex = new NoSubstringIndex(),
    ) {}

    /**
     * Creates whatever the database lacks, so applying it to a database that already has the schema is a no-op.
     */
    public function apply(PDO $pdo): void
    {
        foreach ($this->statements() as $statement) {
            $pdo->exec($statement);
        }

        $this->stampVersion($pdo);
    }

    /**
     * The same schema apply() creates as a runnable SQL script, to export to a file or feed to a migration tool.
     */
    public function ddl(): string
    {
        $indexStatements = $this->substringIndex->schemaStatements($this->dialect);
        $baseline = $this->dialect->schemaSql();

        if ($indexStatements === []) {
            return $baseline;
        }

        return rtrim($baseline)
            . "\n\n"
            . implode(";\n\n", $indexStatements)
            . ";\n";
    }

    /**
     * @return list<string>
     */
    private function statements(): array
    {
        return [
            ...$this->dialect->schemaStatements(),
            ...$this->substringIndex->schemaStatements($this->dialect),
        ];
    }

    /**
     * Records the schema the tables were created from, so a database states which revision it holds.
     */
    private function stampVersion(PDO $pdo): void
    {
        $statement = $pdo->prepare(<<<SQL
            INSERT INTO ldap_schema_version (id, version)
            SELECT 1, ?
            WHERE NOT EXISTS (SELECT 1 FROM ldap_schema_version WHERE id = 1)
            SQL);
        $statement->execute([self::VERSION]);
    }
}
