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

use PDO;
use PDOException;

/**
 * Re-runs the backend storage suite against real MySQL. Gated on MYSQL_DSN — tests are skipped
 * when the env var is absent or the server is unreachable, so the suite is a no-op on dev boxes
 * without MySQL but exercised in CI.
 *
 * Every test restarts the shared server so the bootstrap's DROP + re-import runs fresh. The
 * parent's destructive tests rely on pcntl fork isolation for reset, which does not apply to a
 * persistent backend.
 */
final class MysqlLdapBackendStorageTest extends LdapBackendStorageTestCase
{
    public static function setUpBeforeClass(): void
    {
        if (!extension_loaded('pcntl') || !self::isMysqlAvailable()) {
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
        if (!self::isMysqlAvailable()) {
            self::markTestSkipped('MySQL is not available (set MYSQL_DSN and ensure the server is reachable).');
        }

        parent::setUp();
    }

    public function tearDown(): void
    {
        $this->stopServer();

        parent::tearDown();
    }

    /**
     * Declared so a test that restarts the server gets this backend rather than the command's default.
     */
    protected static function storageExtraArgs(): array
    {
        return ['--storage=mysql'];
    }

    private static function isMysqlAvailable(): bool
    {
        if (!extension_loaded('pdo_mysql')) {
            return false;
        }

        $dsn = getenv('MYSQL_DSN');

        if ($dsn === false || $dsn === '') {
            return false;
        }

        try {
            new PDO(
                $dsn,
                getenv('MYSQL_USER') ?: 'root',
                getenv('MYSQL_PASSWORD') ?: 'root',
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_TIMEOUT => 2,
                ],
            );
        } catch (PDOException) {
            return false;
        }

        return true;
    }
}
