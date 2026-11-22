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

namespace Tests\Integration\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Exception\CancelRequestException;

/**
 * refreshAndPersist under the Swoole runner.
 */
final class SyncReplSwoolePersistTest extends SyncReplPersistTestCase
{
    public static function setUpBeforeClass(): void
    {
        if (!extension_loaded('swoole')) {
            return;
        }

        static::initSharedServer(
            'ldap-server',
            'tcp',
            [
                ...static::persistServerArgs(),
                '--runner=swoole',
            ],
        );
    }

    public static function tearDownAfterClass(): void
    {
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->requireSwoole();

        parent::setUp();
    }

    public function testAnInMemoryServerSetToSeveralWorkersServesAPersist(): void
    {
        $this->createServerProcess(
            'tcp',
            [
                '--storage=memory',
                '--seed=' . self::SEED_LDIF,
                '--allow-sync',
                '--runner=swoole',
                '--workers=2',
            ],
        );
        $refreshed = false;

        $this->boundSync()
            ->useRefreshDoneHandler(static function () use (&$refreshed): void {
                $refreshed = true;

                throw new CancelRequestException();
            })
            ->listen();

        self::assertTrue($refreshed);
    }
}
