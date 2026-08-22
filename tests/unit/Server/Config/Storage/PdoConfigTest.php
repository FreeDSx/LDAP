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

namespace Tests\Unit\FreeDSx\Ldap\Server\Config\Storage;

use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoDriver;
use FreeDSx\Ldap\Server\Config\Storage\StorageType;
use FreeDSx\Ldap\Server\Config\Storage\SubstringIndexMode;
use PDO;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PdoConfigTest extends TestCase
{
    public function test_its_type_is_pdo(): void
    {
        self::assertSame(
            StorageType::Pdo,
            PdoConfig::forSqlite(':memory:')->type(),
        );
    }

    public function test_sqlite_carries_the_sqlite_driver(): void
    {
        self::assertSame(
            PdoDriver::Sqlite,
            PdoConfig::forSqlite(':memory:')->getDriver(),
        );
    }

    public function test_sqlite_prefixes_the_path_into_a_dsn(): void
    {
        self::assertSame(
            'sqlite:/var/lib/ldap.sqlite',
            PdoConfig::forSqlite('/var/lib/ldap.sqlite')->getDsn(),
        );
    }

    public function test_sqlite_needs_no_credentials(): void
    {
        $config = PdoConfig::forSqlite(':memory:');

        self::assertNull($config->getUsername());
        self::assertNull($config->getPassword());
    }

    public function test_mysql_carries_the_mysql_driver_and_credentials(): void
    {
        $config = PdoConfig::forMysql(
            'mysql:host=localhost;dbname=ldap',
            'user',
            'secret',
        );

        self::assertSame(
            PdoDriver::Mysql,
            $config->getDriver(),
        );
        self::assertSame(
            'mysql:host=localhost;dbname=ldap',
            $config->getDsn(),
        );
        self::assertSame(
            'user',
            $config->getUsername(),
        );
        self::assertSame(
            'secret',
            $config->getPassword(),
        );
    }

    public function test_it_takes_its_session_statements_from_the_driver(): void
    {
        self::assertSame(
            PdoDriver::Sqlite->defaultSessionStatements(),
            PdoConfig::forSqlite(':memory:')->getSessionStatements(),
        );
    }

    public function test_it_takes_its_pdo_options_from_the_driver(): void
    {
        self::assertSame(
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
            PdoConfig::forSqlite(':memory:')->getPdoOptions(),
        );
    }

    public function test_sqlite_serializes_writes_by_default(): void
    {
        self::assertTrue(PdoConfig::forSqlite(':memory:')->getSerializeSwooleWrites());
    }

    public function test_mysql_does_not_serialize_writes_by_default(): void
    {
        $config = PdoConfig::forMysql(
            'mysql:host=localhost;dbname=ldap',
            'user',
            'secret',
        );

        self::assertFalse($config->getSerializeSwooleWrites());
    }

    public function test_it_initializes_the_schema_by_default(): void
    {
        self::assertTrue(PdoConfig::forSqlite(':memory:')->getInitializeSchema());
    }

    public function test_its_substring_index_mode_defaults_to_auto(): void
    {
        self::assertSame(
            SubstringIndexMode::Auto,
            PdoConfig::forSqlite(':memory:')->getSubstringIndexMode(),
        );
    }

    public function test_the_setters_override_the_driver_defaults(): void
    {
        $config = PdoConfig::forSqlite(':memory:')
            ->setSessionStatements(['PRAGMA foreign_keys = OFF'])
            ->setSerializeSwooleWrites(false)
            ->setInitializeSchema(false)
            ->setSubstringIndexMode(SubstringIndexMode::None);

        self::assertSame(
            ['PRAGMA foreign_keys = OFF'],
            $config->getSessionStatements(),
        );
        self::assertFalse($config->getSerializeSwooleWrites());
        self::assertFalse($config->getInitializeSchema());
        self::assertSame(
            SubstringIndexMode::None,
            $config->getSubstringIndexMode(),
        );
    }

    public function test_a_file_backed_sqlite_database_is_multi_process_safe(): void
    {
        self::assertTrue(PdoConfig::forSqlite('/var/lib/ldap.sqlite')->isMultiProcessSafe());
    }

    public function test_mysql_is_multi_process_safe(): void
    {
        self::assertTrue(
            PdoConfig::forMysql(
                'mysql:host=localhost;dbname=ldap',
                'user',
                'secret',
            )->isMultiProcessSafe(),
        );
    }

    #[DataProvider('inMemorySqliteDsnProvider')]
    public function test_an_in_memory_sqlite_database_is_not_multi_process_safe(string $path): void
    {
        self::assertFalse(PdoConfig::forSqlite($path)->isMultiProcessSafe());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function inMemorySqliteDsnProvider(): iterable
    {
        yield 'the bare in-memory path' => [':memory:'];
        yield 'mixed case, since a DSN is not case sensitive here' => [':MEMORY:'];
        yield 'a shared cache URI' => ['file:ldap?mode=memory&cache=shared'];
        yield 'mixed case on the URI parameter' => ['file:ldap?mode=MEMORY'];
    }
}
