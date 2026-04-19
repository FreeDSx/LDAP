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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filter\ApproximateFilter;
use FreeDSx\Ldap\Search\Filters;

/**
 * Runs the full LdapBackendStorageTest suite against SqliteStorage,
 * and adds a test that verifies writes persist across separate client connections.
 *
 * Uses the same ldap-backend-storage.php bootstrap script with the 'sqlite' handler,
 * which seeds a SqliteStorage and recreates the database file on each startup.
 *
 * Each mutating test restarts the server so the database is recreated cleanly,
 * preventing cross-test pollution.
 */
final class LdapBackendSqliteStorageTest extends LdapBackendStorageTest
{
    /**
     * Tests that mutate the database and would pollute subsequent tests.
     */
    private const MUTATING_TESTS = [
        'testAddStoresEntry',
        'testDeleteRemovesEntry',
        'testModifyReplacesAttributeValue',
        'testRenameChangesRdn',
        'testWritesPersistAcrossConnections',
    ];

    public static function setUpBeforeClass(): void
    {
        // Intentionally skip LdapBackendStorageTest::setUpBeforeClass() to
        // avoid starting the InMemory server. Start the SQLite-storage server.
        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            'sqlite',
        );
    }

    public static function tearDownAfterClass(): void
    {
        LdapBackendSqliteStorageTest::tearDownSharedServer();
    }

    public function setUp(): void
    {
        parent::setUp();

        if (in_array($this->name(), self::MUTATING_TESTS, true)) {
            $this->stopServer();
            $this->createServerProcess(
                'tcp',
                'sqlite',
            );
        }
    }

    public function testWritesPersistAcrossConnections(): void
    {
        $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            '12345'
        );

        $this->ldapClient()->create(Entry::fromArray(
            'cn=persistent,dc=foo,dc=bar',
            ['cn' => 'persistent', 'objectClass' => 'inetOrgPerson']
        ));

        $this->ldapClient()->unbind();

        $secondClient = $this->buildClient('tcp');
        $secondClient->bind(
            'cn=user,dc=foo,dc=bar',
            '12345'
        );

        $entries = $secondClient->search(
            Operations::search(Filters::equal('cn', 'persistent'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
        );

        $secondClient->unbind();

        self::assertCount(
            1,
            $entries
        );
        self::assertSame(
            'cn=persistent,dc=foo,dc=bar',
            $entries->first()?->getDn()->toString()
        );
    }

    public function testApproximateWithAsciiValueMatches(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(new ApproximateFilter('cn', 'Alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'cn=alice,ou=people,dc=foo,dc=bar',
            $entries->first()?->getDn()->toString()
        );
    }

    /**
     * Canary: if translateGte is wrongly marked exact for a digit value, SQL byte-compare ("99">"100") returns alice.
     */
    public function testGteDigitFilterExcludesLowerNumericValueEvenThoughBytewiseCompareWouldMatch(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::greaterThanOrEqual('uidNumber', '100'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
        );

        self::assertCount(0, $entries);
    }

    public function testGteAsciiNonDigitValueMatchesLexicographically(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::greaterThanOrEqual('sn', 'Smith'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'cn=alice,ou=people,dc=foo,dc=bar',
            $entries->first()?->getDn()->toString()
        );
    }
}
