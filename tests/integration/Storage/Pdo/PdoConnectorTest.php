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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnector;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoSchema;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use PDO;
use PDOException;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Pdo\SqliteTableNamesTrait;

final class PdoConnectorTest extends TestCase
{
    use SqliteTableNamesTrait;

    private PdoConfig $config;

    private PdoConnector $subject;

    protected function setUp(): void
    {
        $this->config = PdoConfig::forSqlite(':memory:');
        $this->subject = new PdoConnector(
            $this->config,
            new PdoSchema(new SqliteDialect()),
        );
    }

    public function test_bootstrapping_applies_the_schema(): void
    {
        self::assertContains(
            'entries',
            $this->tableNames($this->subject->bootstrap()),
        );
    }

    public function test_bootstrapping_with_schema_setup_disabled_creates_nothing(): void
    {
        $this->config->setInitializeSchema(false);

        self::assertSame(
            [],
            $this->tableNames($this->subject->bootstrap()),
        );
    }

    public function test_opening_a_connection_never_applies_the_schema(): void
    {
        self::assertSame(
            [],
            $this->tableNames($this->subject->open()),
        );
    }

    public function test_an_opened_connection_fetches_rows_by_column_name_only(): void
    {
        $this->config->setPdoOptions([]);

        $statement = $this->subject->open()->query('SELECT 1 AS one');
        self::assertNotFalse($statement);

        self::assertSame(
            ['one' => 1],
            $statement->fetch(),
        );
    }

    public function test_an_opened_connection_throws_on_a_failed_statement(): void
    {
        $this->config->setPdoOptions([PDO::ATTR_ERRMODE => PDO::ERRMODE_SILENT]);

        $this->expectException(PDOException::class);

        $this->subject->open()->exec('NOT SQL');
    }
}
