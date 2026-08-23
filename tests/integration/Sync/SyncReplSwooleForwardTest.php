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
 * A ppolicy-forwarding replica under the Swoole runner, exercising the serialized PDO replica password-state store.
 */
final class SyncReplSwooleForwardTest extends SyncReplForwardTestCase
{
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('swoole')) {
            return;
        }

        static::initSharedServer(
            'ldap-replica',
            'tcp',
            ['--forward', '--runner=swoole'],
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->requireSwoole();

        parent::setUp();
    }
}
