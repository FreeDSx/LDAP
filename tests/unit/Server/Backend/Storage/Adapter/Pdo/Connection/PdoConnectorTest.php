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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection;

use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnector;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoSchema;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use PDO;
use PDOException;
use PHPUnit\Framework\TestCase;

final class PdoConnectorTest extends TestCase
{
    private PdoSchema $schema;

    protected function setUp(): void
    {
        $this->schema = new PdoSchema(new SqliteDialect());
    }

    public function test_it_opens_a_connection_that_throws_and_fetches_associative_rows(): void
    {
        $pdo = (new PdoConnector(
            PdoConfig::forSqlite(':memory:'),
            $this->schema,
        ))->open();

        self::assertSame(
            PDO::ERRMODE_EXCEPTION,
            $pdo->getAttribute(PDO::ATTR_ERRMODE),
        );
        self::assertSame(
            PDO::FETCH_ASSOC,
            $pdo->getAttribute(PDO::ATTR_DEFAULT_FETCH_MODE),
        );
    }

    public function test_a_database_that_cannot_be_opened_is_answered_as_unavailable(): void
    {
        $subject = new PdoConnector(
            PdoConfig::forSqlite(sys_get_temp_dir() . '/freedsx-missing-' . uniqid() . '/storage.sqlite'),
            $this->schema,
        );

        try {
            $subject->open();
            self::fail('Expected the open to fail.');
        } catch (StorageIoException $e) {
            self::assertSame(
                ResultCode::UNAVAILABLE,
                $e->getCode(),
            );
            self::assertInstanceOf(
                PDOException::class,
                $e->getPrevious(),
            );
        }
    }
}
