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

use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\Storage\StorageConfigInterface;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Pdo\ThrowawayMysqlDatabase;
use Tests\Support\FreeDSx\Ldap\Storage\LinkedUidStorageContractTests;

/**
 * Holds MySQL to the linked uid contract, in a database of its own per test and gated on MYSQL_DSN.
 */
final class MysqlLinkedUidStorageTest extends TestCase
{
    use LinkedUidStorageContractTests;

    private ?ThrowawayMysqlDatabase $database = null;

    private PdoConfig $storage;

    protected function setUp(): void
    {
        $database = ThrowawayMysqlDatabase::create();

        if ($database === null) {
            self::markTestSkipped('MySQL is not available (set MYSQL_DSN and ensure the server is reachable).');
        }
        $this->database = $database;
        $this->storage = $database->config();
    }

    protected function tearDown(): void
    {
        $this->database?->drop();
    }

    protected function uidLinkStorage(): StorageConfigInterface
    {
        return $this->storage;
    }
}
