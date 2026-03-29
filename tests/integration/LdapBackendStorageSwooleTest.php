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

namespace Tests\Integration\FreeDSx\Ldap;

/**
 * Runs the full LdapBackendStorageTest suite against the SwooleServerRunner.
 *
 * Read-only tests share a single Swoole server process started in
 * setUpBeforeClass(). Write tests that mutate the InMemoryStorageAdapter
 * state stop the shared server and spin up a fresh one in setUp() — giving
 * Swoole's coroutine startup the same natural gap between setUp() and the
 * first LDAP call that the original per-test approach relied on. tearDown()
 * then restarts the shared server so subsequent tests see a clean seed.
 *
 * Skipped automatically when the swoole extension is not loaded.
 */
final class LdapBackendStorageSwooleTest extends LdapBackendStorageTest
{
    /**
     * Tests that write to the InMemoryStorageAdapter and would pollute the
     * shared server's state for subsequent tests.
     */
    private const MUTATING_TESTS = [
        'testAddStoresEntry',
        'testDeleteRemovesEntry',
        'testModifyReplacesAttributeValue',
        'testRenameChangesRdn',
    ];

    /**
     * Start a single shared Swoole server instead of the PCNTL server that
     * LdapBackendStorageTest::setUpBeforeClass() would launch.
     */
    public static function setUpBeforeClass(): void
    {
        // Intentionally skip parent::setUpBeforeClass() to avoid starting the
        // shared PCNTL server that LdapBackendStorageTest would launch.
        if (!extension_loaded('swoole')) {
            return;
        }

        static::initSharedServer(
            'ldapbackendstorage',
            'tcp',
            'swoole',
        );
    }

    public static function tearDownAfterClass(): void
    {
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        if (!extension_loaded('swoole')) {
            $this->markTestSkipped('The swoole extension is required to run SwooleServerRunner tests.');
        }

        // parent::setUp() connects the per-test client to the shared server.
        parent::setUp();

        // Mutating tests need a fresh isolated server. Doing this in setUp()
        // rather than inline in the test method ensures Swoole's coroutine has
        // the same natural setUp→test gap to finish binding the socket.
        if (in_array($this->name(), self::MUTATING_TESTS, true)) {
            $this->stopServer();
            $this->createServerProcess('tcp', 'swoole');
        }
    }
}
