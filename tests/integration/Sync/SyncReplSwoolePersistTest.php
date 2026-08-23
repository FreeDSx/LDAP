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
}
