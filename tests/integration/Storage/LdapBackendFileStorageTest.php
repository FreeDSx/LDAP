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
use FreeDSx\Ldap\Search\Filters;

/**
 * Runs the full LdapBackendStorageTest suite against JsonFileStorageAdapter,
 * and adds a test that verifies writes persist across separate client connections.
 *
 * Uses the same ldap-backend-storage.php bootstrap script with the 'file' handler,
 * which seeds a JsonFileStorageAdapter and recreates the JSON file on each startup.
 *
 * Each mutating test restarts the server so the seeded JSON file is recreated
 * cleanly, preventing cross-test pollution.
 */
final class LdapBackendFileStorageTest extends LdapBackendStorageTest
{
    /**
     * Tests that mutate the JSON file and would pollute subsequent tests.
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
        // avoid starting the InMemory server. Start the file-storage server.
        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer('ldap-backend-storage', 'tcp', 'file');
    }

    public static function tearDownAfterClass(): void
    {
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        parent::setUp();

        if (in_array($this->name(), self::MUTATING_TESTS, true)) {
            // Stop the shared server so the bin script recreates the JSON file.
            $this->stopServer();
            $this->createServerProcess(
                'tcp',
                'file'
            );
        }
    }

    public function testWritesPersistAcrossConnections(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->ldapClient()->create(Entry::fromArray(
            'cn=persistent,dc=foo,dc=bar',
            ['cn' => 'persistent', 'objectClass' => 'inetOrgPerson']
        ));

        // Close the first connection so the PCNTL child exits and flushes.
        $this->ldapClient()->unbind();

        // A brand-new connection to the same server must see the persisted entry.
        $secondClient = $this->buildClient('tcp');
        $secondClient->bind('cn=user,dc=foo,dc=bar', '12345');

        $entries = $secondClient->search(
            Operations::search(Filters::equal('cn', 'persistent'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
        );

        $secondClient->unbind();

        self::assertCount(1, $entries);
        self::assertSame(
            'cn=persistent,dc=foo,dc=bar',
            $entries->first()?->getDn()->toString()
        );
    }
}
