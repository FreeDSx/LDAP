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

namespace Tests\Integration\FreeDSx\Ldap\Sync\Consumer;

use FreeDSx\Ldap\Server\Backend\Storage\Capability\DeferredLinksInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Sync\Consumer\ReplicaMoves;
use FreeDSx\Ldap\Sync\Consumer\VerbatimStorageApplier;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Pdo\ThrowawayMysqlDatabase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use Tests\Support\FreeDSx\Ldap\Sync\VerbatimStorageApplierTests;

/**
 * Holds the verbatim applier to its shared behaviour on MySQL, in a database of its own per test and gated on MYSQL_DSN.
 */
final class VerbatimStorageApplierMysqlTest extends TestCase
{
    use ServerContainerTrait;
    use VerbatimStorageApplierTests;

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
        $lister = $this->fromContainer(ListEntryInterface::class);
        $this->reader = $this->fromContainer(ReadEntryInterface::class);
        $this->writer = $this->fromContainer(WriteEntryInterface::class);
        $this->subject = new VerbatimStorageApplier(
            $lister,
            $this->writer,
            $this->reader,
            $this->fromContainer(TransactionalWriteInterface::class),
            new ReplicaMoves(
                $this->reader,
                $lister,
                $this->writer,
            ),
            $this->fromContainer(DeferredLinksInterface::class),
        );
    }

    protected function tearDown(): void
    {
        $this->database?->drop();
    }

    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::forStorage($this->storage);
    }
}
