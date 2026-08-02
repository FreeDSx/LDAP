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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\SyncRepl;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * End-to-end RFC 4533 refreshOnly sync against the built-in FreeDSx server.
 */
final class SyncReplNativeTest extends ServerTestCase
{
    private const SEED_LDIF = __DIR__ . '/../../resources/seed/sync-seed.ldif';

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-server',
            'tcp',
            [
                '--seed=' . self::SEED_LDIF,
                '--allow-sync',
            ],
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-server');

        parent::setUp();
    }

    public function testItStreamsEveryEntryOnAFreshRefreshOnlyPoll(): void
    {
        $this->authenticateUser();

        $dns = $this->collectPoll(
            $this->syncRepl(),
        );
        sort($dns);

        // A cookieless poll runs the present phase: the whole subtree comes across, nothing more.
        self::assertSame(
            [
                'cn=admin,dc=foo,dc=bar',
                'cn=alice,ou=people,dc=foo,dc=bar',
                'cn=bob,ou=people,dc=foo,dc=bar',
                'cn=carol,ou=people,dc=foo,dc=bar',
                'cn=lockme,ou=people,dc=foo,dc=bar',
                'cn=resetme,ou=people,dc=foo,dc=bar',
                'cn=user,dc=foo,dc=bar',
                'dc=foo,dc=bar',
                'ou=people,dc=foo,dc=bar',
            ],
            $dns,
        );
    }

    public function testAPollWithAFilterOnlyStreamsMatchingEntries(): void
    {
        $this->authenticateUser();

        $dns = $this->collectPoll(
            $this->syncRepl(Filters::equal('objectClass', 'organizationalUnit')),
        );

        self::assertSame(
            ['ou=people,dc=foo,dc=bar'],
            $dns,
        );
    }

    public function testAnIncrementalPollWithACookieReturnsOnlyChangesSinceTheCookie(): void
    {
        // Writes below need an administrator, who also holds the privileged sync control.
        $this->authenticateAdmin();

        $cookie = null;
        $initial = $this->syncRepl();
        $initial->useCookieHandler(function (string $value) use (&$cookie): void {
            $cookie = $value;
        });
        $initial->poll();

        self::assertNotNull(
            $cookie,
            'The refresh phase must hand back a cookie for the next poll.',
        );

        $this->ldapClient()->create(Entry::fromArray(
            'cn=dave,ou=people,dc=foo,dc=bar',
            [
                'cn' => 'dave',
                'sn' => 'Davis',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $incremental = $this->syncRepl();
        $incremental->useCookie($cookie);
        $dns = $this->collectPoll($incremental);

        // Only the entry added after the cookie is streamed; the untouched baseline is not resent.
        self::assertSame(
            ['cn=dave,ou=people,dc=foo,dc=bar'],
            $dns,
        );
    }

    private function syncRepl(?FilterInterface $filter = null): SyncRepl
    {
        $syncRepl = $this->ldapClient()->syncRepl($filter);
        $syncRepl->request()
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        return $syncRepl;
    }

    /**
     * @return list<string>
     */
    private function collectPoll(SyncRepl $syncRepl): array
    {
        $dns = [];
        $syncRepl->poll(function (SyncEntryResult $result) use (&$dns): void {
            $dns[] = strtolower($result->getEntry()->getDn()->toString());
        });

        return $dns;
    }
}
