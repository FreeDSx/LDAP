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

namespace Tests\Integration\FreeDSx\Ldap\Journal;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\TestWorker;

/**
 * A journal kept purely for auditing, which must not also turn the server into a sync provider.
 */
final class LdapAuditJournalTest extends ServerTestCase
{
    private static string $auditLog;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        self::$auditLog = TestWorker::path('audit.jsonl');
        self::removeAuditLog();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            ['--journal=audit'],
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
        self::removeAuditLog();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-backend-storage');

        parent::setUp();
    }

    public function test_a_write_is_recorded_to_the_audit_log(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=audited,dc=foo,dc=bar',
            [
                'cn' => 'audited',
                'sn' => 'Audited',
                'objectClass' => 'person',
            ],
        ));

        self::assertStringContainsString(
            'cn=audited,dc=foo,dc=bar',
            $this->readAuditLog(),
        );
    }

    public function test_sync_is_not_served_while_only_auditing(): void
    {
        $this->authenticateAdmin();

        $syncRepl = $this->ldapClient()->syncRepl();
        $syncRepl->request()
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $syncRepl->poll(static fn() => null);
    }

    private static function removeAuditLog(): void
    {
        if (file_exists(self::$auditLog)) {
            unlink(self::$auditLog);
        }
    }

    /**
     * The sink writes from the server process, so the record may not have landed the moment the write returns.
     */
    private function readAuditLog(float $timeoutSeconds = 5.0): string
    {
        $deadline = microtime(true) + $timeoutSeconds;

        do {
            clearstatcache();
            $contents = file_exists(self::$auditLog)
                ? (string) file_get_contents(self::$auditLog)
                : '';

            if ($contents !== '') {
                return $contents;
            }

            usleep(25_000);
        } while (microtime(true) < $deadline);

        return '';
    }
}
