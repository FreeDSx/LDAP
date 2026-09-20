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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Pdo;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\MysqlDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoSchema;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\TrigramSubstringIndex;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Pdo\SqliteTableNamesTrait;

final class PdoSchemaTest extends TestCase
{
    use SqliteTableNamesTrait;

    private const BASELINE_TABLES = [
        'entries',
        'entry_attribute_links',
        'entry_attribute_values',
        'entry_link_pending',
        'ldap_change_journal',
        'ldap_change_journal_seq',
        'ldap_replica_pwpolicy_state',
        'ldap_schema_version',
    ];

    private PDO $pdo;

    private PdoSchema $subject;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->subject = new PdoSchema(new SqliteDialect());
    }

    public function test_applying_creates_the_baseline_tables(): void
    {
        $this->subject->apply($this->pdo);

        self::assertSame(
            self::BASELINE_TABLES,
            $this->tableNames($this->pdo),
        );
    }

    public function test_applying_to_a_database_that_has_the_schema_changes_nothing(): void
    {
        $this->subject->apply($this->pdo);
        $this->subject->apply($this->pdo);

        self::assertSame(
            self::BASELINE_TABLES,
            $this->tableNames($this->pdo),
        );
        self::assertSame(
            1,
            $this->intQuery('SELECT COUNT(*) FROM ldap_schema_version'),
        );
    }

    public function test_applying_stamps_the_current_version(): void
    {
        $this->subject->apply($this->pdo);

        self::assertSame(
            PdoSchema::VERSION,
            $this->intQuery('SELECT version FROM ldap_schema_version WHERE id = 1'),
        );
    }

    public function test_applying_with_a_substring_index_creates_its_table(): void
    {
        $subject = new PdoSchema(
            new SqliteDialect(),
            new TrigramSubstringIndex(),
        );

        $subject->apply($this->pdo);

        self::assertContains(
            'entry_attribute_trigrams',
            $this->tableNames($this->pdo),
        );
    }

    public function test_the_ddl_without_a_substring_index_is_the_dialect_baseline(): void
    {
        $dialect = new SqliteDialect();

        self::assertSame(
            $dialect->schemaSql(),
            (new PdoSchema($dialect))->ddl(),
        );
    }

    public function test_the_mysql_ddl_is_the_mysql_baseline(): void
    {
        $ddl = (new PdoSchema(new MysqlDialect()))->ddl();

        self::assertStringContainsString(
            'CREATE TABLE IF NOT EXISTS entries',
            $ddl,
        );
        self::assertStringContainsString(
            'ENGINE=InnoDB',
            $ddl,
        );
    }

    public function test_the_ddl_includes_the_substring_index_tables(): void
    {
        $ddl = (new PdoSchema(
            new SqliteDialect(),
            new TrigramSubstringIndex(),
        ))->ddl();

        self::assertStringContainsString(
            'entry_attribute_trigrams',
            $ddl,
        );
    }

    public function test_running_the_exported_ddl_creates_the_tables_applying_would(): void
    {
        $subject = new PdoSchema(
            new SqliteDialect(),
            new TrigramSubstringIndex(),
        );
        $applied = new PDO('sqlite::memory:');
        $subject->apply($applied);

        $this->pdo->exec($subject->ddl());

        self::assertSame(
            $this->tableNames($applied),
            $this->tableNames($this->pdo),
        );
    }

    private function intQuery(string $sql): int
    {
        $statement = $this->pdo->query($sql);
        self::assertNotFalse($statement);

        $value = $statement->fetchColumn();
        self::assertIsNumeric($value);

        return (int) $value;
    }
}
