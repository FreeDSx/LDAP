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

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Pdo\SqliteTableNamesTrait;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class PdoStorageContainerProviderTest extends TestCase
{
    use ServerContainerTrait;

    use SqliteTableNamesTrait;

    private string $path;

    protected function setUp(): void
    {
        $path = tempnam(
            sys_get_temp_dir(),
            'pdo-provider-',
        );
        self::assertIsString($path);
        $this->path = $path;
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function test_a_reconnect_does_not_apply_the_schema_again(): void
    {
        $container = Container::forServer(
            TestServerOptions::forStorage(PdoConfig::forSqlite($this->path)),
        );
        $connection = $container->get(PdoConnection::class);
        $probe = new PDO('sqlite:' . $this->path);
        $probe->exec('DROP TABLE ldap_schema_version');

        $connection->reset();
        $container->get(ReadEntryInterface::class)
            ->exists(new Dn('dc=example,dc=com'));

        self::assertNotContains(
            'ldap_schema_version',
            $this->tableNames($probe),
        );
    }

    public function test_disabling_schema_setup_leaves_the_database_empty(): void
    {
        $connection = $this->fromContainer(
            PdoConnection::class,
            options: TestServerOptions::forStorage(
                PdoConfig::forSqlite($this->path)
                    ->setInitializeSchema(false),
            ),
        );

        self::assertSame(
            [],
            $this->tableNames(new PDO('sqlite:' . $this->path)),
        );
        unset($connection);
    }

    public function test_the_swoole_runner_refuses_an_in_memory_database(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('an in-memory SQLite database is not supported');

        $this->fromContainer(
            PdoConnection::class,
            options: TestServerOptions::sqlite()
                ->setRunnerConfig(new RunnerConfig(RunnerMode::Swoole)),
        );
    }
}
