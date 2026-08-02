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

use Closure;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\CancelRequestException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Session;
use FreeDSx\Ldap\Sync\SyncRepl;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * Shared end-to-end RFC 4533 refreshAndPersist coverage.
 */
abstract class SyncReplPersistTestCase extends ServerTestCase
{
    protected const SEED_LDIF = __DIR__ . '/../../resources/seed/sync-seed.ldif';

    private const LISTEN_READ_TIMEOUT = 20;

    public function setUp(): void
    {
        $this->setServerMode('ldap-server');

        parent::setUp();
    }

    public function testListenReceivesAnAddMadeDuringThePersistPhase(): void
    {
        $dn = 'cn=persist-add,dc=foo,dc=bar';
        $cookies = [];
        $seenRefresh = false;
        $result = null;
        $wrote = false;

        $syncRepl = $this->boundSync();
        $syncRepl->useCookieHandler(function (string $cookie) use (&$cookies): void {
            $cookies[] = $cookie;
        });

        $syncRepl->listen(function (SyncEntryResult $entry, Session $session) use (&$seenRefresh, &$result, &$wrote, $dn): void {
            if (!$session->isRefreshComplete()) {
                $seenRefresh = true;

                if (!$wrote) {
                    $wrote = true;
                    $this->onAnotherConnection(fn(LdapClient $w) => $w->create(Entry::fromArray(
                        $dn,
                        [
                            'cn' => 'persist-add',
                            'sn' => 'Added',
                            'objectClass' => 'inetOrgPerson',
                        ],
                    )));
                }

                return;
            }

            $result = $entry;

            throw new CancelRequestException();
        });

        self::assertTrue($seenRefresh);
        self::assertInstanceOf(
            SyncEntryResult::class,
            $result,
        );
        self::assertTrue(
            $result->isAdd(),
            'The persisted change is delivered as an add state.',
        );
        self::assertSame(
            $dn,
            strtolower($result->getEntry()->getDn()->toString()),
        );
        self::assertNotEmpty(
            $cookies,
            'The refresh boundary and persist phase advance the cookie via SyncInfo messages.',
        );
    }

    public function testPersistDeliversADeletion(): void
    {
        $dn = 'cn=persist-delete,dc=foo,dc=bar';
        $result = null;
        $wrote = false;

        $syncRepl = $this->boundSync();

        $syncRepl->listen(function (SyncEntryResult $entry, Session $session) use (&$result, &$wrote, $dn): void {
            if (!$session->isRefreshComplete()) {
                if (!$wrote) {
                    $wrote = true;
                    // Add then delete the same entry after the refresh boundary.
                    $this->onAnotherConnection(function (LdapClient $w) use ($dn): void {
                        $w->create(Entry::fromArray(
                            $dn,
                            [
                                'cn' => 'persist-delete',
                                'sn' => 'Doomed',
                                'objectClass' => 'inetOrgPerson',
                            ],
                        ));
                        $w->delete($dn);
                    });
                }

                return;
            }

            $result = $entry;

            throw new CancelRequestException();
        });

        self::assertInstanceOf(
            SyncEntryResult::class,
            $result,
        );
        self::assertTrue(
            $result->isDelete(),
            'A removal is delivered with the delete sync state.',
        );
        self::assertSame(
            $dn,
            strtolower($result->getEntry()->getDn()->toString()),
        );
    }

    public function testListenResumesFromACookieWithAnIncrementalRefresh(): void
    {
        $dn = 'cn=persist-resume,dc=foo,dc=bar';

        // A cookieless poll gives us the current position, then a change is made past it.
        $cookie = $this->currentCookie();
        $this->onAnotherConnection(fn(LdapClient $w) => $w->create(Entry::fromArray(
            $dn,
            [
                'cn' => 'persist-resume',
                'sn' => 'Resumed',
                'objectClass' => 'inetOrgPerson',
            ],
        )));

        $seen = null;

        $syncRepl = $this->boundSync();
        $syncRepl->useCookie($cookie);

        // Resuming from the cookie makes the refresh phase incremental (a SyncRefreshDelete boundary)
        $syncRepl->listen(function (SyncEntryResult $entry) use (&$seen): void {
            $seen = strtolower($entry->getEntry()->getDn()->toString());

            throw new CancelRequestException();
        });

        self::assertSame(
            $dn,
            $seen,
        );
    }

    /**
     * Server flags shared by every runner.
     *
     * @return list<string>
     */
    protected static function persistServerArgs(): array
    {
        return [
            '--storage=sqlite',
            '--seed=' . self::SEED_LDIF,
            '--allow-sync',
        ];
    }

    private function currentCookie(): string
    {
        $cookie = null;
        $sync = $this->boundSync();
        $sync->useCookieHandler(function (string $value) use (&$cookie): void {
            $cookie = $value;
        });
        $sync->poll();

        self::assertNotNull(
            $cookie,
            'A poll returns the current sync cookie.',
        );

        return $cookie;
    }

    private function onAnotherConnection(Closure $do): void
    {
        $writer = $this->buildClient('tcp');

        try {
            $writer->bind('cn=admin,dc=foo,dc=bar', '12345');
            $do($writer);
        } finally {
            $writer->unbind();
        }
    }

    private function boundSync(): SyncRepl
    {
        $client = $this->listenClient();
        $client->bind('cn=user,dc=foo,dc=bar', '12345');

        $syncRepl = $client->syncRepl();
        $syncRepl->request()
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        return $syncRepl;
    }

    private function listenClient(): LdapClient
    {
        return $this->getClient(
            $this->makeOptions()
                ->setPort(10389)
                ->setTransport('tcp')
                ->setServers(['127.0.0.1'])
                ->setSslValidateCert(false)
                ->setTimeoutRead(self::LISTEN_READ_TIMEOUT),
        );
    }
}
