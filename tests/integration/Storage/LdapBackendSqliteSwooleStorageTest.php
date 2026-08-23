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
 * Runs the storage suite against SQLite on the Swoole runner.
 */
final class LdapBackendSqliteSwooleStorageTest extends LdapBackendStorageTestCase
{
    /**
     * Tests that mutate the database and would pollute subsequent tests.
     */
    private const MUTATING_TESTS = [
        'testAddStoresEntry',
        'testDeleteRemovesEntry',
        'testModifyReplacesAttributeValue',
        'testRenameChangesRdn',
    ];

    public static function setUpBeforeClass(): void
    {
        // Intentionally skips the parent, which would start the in-memory PCNTL server.
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

        if (in_array($this->name(), self::MUTATING_TESTS, true)) {
            $this->stopServer();
            $this->createServerProcess(
                'tcp',
                static::storageExtraArgs(),
            );
        }
    }

    protected static function storageExtraArgs(): array
    {
        return ['--storage=sqlite', '--runner=swoole'];
    }
}
