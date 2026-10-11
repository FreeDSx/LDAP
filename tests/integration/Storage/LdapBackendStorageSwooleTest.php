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

namespace Tests\Integration\FreeDSx\Ldap\Storage;

/**
 * Runs the full LdapBackendStorageTestCase suite against the SwooleServerRunner.
 *
 * Every test shares a single Swoole server process started in setUpBeforeClass().
 *
 * Skipped automatically when the swoole extension is not loaded.
 */
final class LdapBackendStorageSwooleTest extends LdapBackendStorageTestCase
{
    /**
     * Start a single shared Swoole server instead of the PCNTL server that
     * LdapBackendStorageTestCase::setUpBeforeClass() would launch.
     */
    public static function setUpBeforeClass(): void
    {
        // Intentionally skip parent::setUpBeforeClass() to avoid starting the
        // shared PCNTL server that LdapBackendStorageTestCase would launch.
        if (!extension_loaded('swoole')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            static::storageExtraArgs(),
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

    /**
     * In-memory storage is stated rather than inherited: Swoole shares one process, which is the only runner it is
     * sound on, and this is the suite's only coverage of that adapter over the wire.
     */
    protected static function storageExtraArgs(): array
    {
        return [...parent::storageExtraArgs(), '--storage=memory', '--runner=swoole'];
    }
}
