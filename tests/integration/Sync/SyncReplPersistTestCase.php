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
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Session;
use FreeDSx\Ldap\Sync\SyncRepl;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\TestWorker;

/**
 * Shared end-to-end RFC 4533 refreshAndPersist coverage.
 */
abstract class SyncReplPersistTestCase extends ServerTestCase
{
    protected const SEED_LDIF = __DIR__ . '/../../resources/seed/sync-seed.ldif';

    private const LISTEN_READ_TIMEOUT = 20;

    /**
     * The provider keepalives every poll, so a read never idles out; this bounds the wait for an expected result.
     */
    private const MAX_PERSIST_RESULTS = 5;

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
        $seen = 0;

        $syncRepl = $this->boundSync();

        $syncRepl->listen(function (SyncEntryResult $entry, Session $session) use (&$result, &$wrote, &$seen, $dn): void {
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
            $seen++;

            // A poll landing between the two writes reports them separately, so the removal can arrive second.
            if ($entry->isDelete() || $seen >= self::MAX_PERSIST_RESULTS) {
                throw new CancelRequestException();
            }
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

    /**
     * RFC 4533 §3.4.2 asks for multiple delete entries to be coalesced into a syncIdSet.
     */
    public function testPersistCoalescesMultipleDeletionsIntoAnIdSet(): void
    {
        $dns = [
            'cn=idset-one,dc=foo,dc=bar',
            'cn=idset-two,dc=foo,dc=bar',
            'cn=idset-three,dc=foo,dc=bar',
        ];
        $idSet = null;

        $syncRepl = $this->boundSync();
        $syncRepl->useIdSetHandler(function (SyncIdSetResult $result) use (&$idSet): void {
            $idSet = $result;

            throw new CancelRequestException();
        });

        $this->listenAfterWriting(
            $syncRepl,
            static function (LdapClient $w) use ($dns): void {
                foreach ($dns as $dn) {
                    $w->create(Entry::fromArray(
                        $dn,
                        [
                            'cn' => explode(',', $dn)[0],
                            'sn' => 'Doomed',
                            'objectClass' => 'inetOrgPerson',
                        ],
                    ));
                }

                foreach ($dns as $dn) {
                    $w->delete($dn);
                }
            },
        );

        self::assertInstanceOf(
            SyncIdSetResult::class,
            $idSet,
            'Several deletions in one journal window are delivered as a single syncIdSet.',
        );
        self::assertTrue($idSet->isDeleted());
        self::assertCount(
            3,
            $idSet,
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

    /**
     * Applies $write on another connection once the refresh phase begins, then persists until the result cap.
     */
    private function listenAfterWriting(
        SyncRepl $syncRepl,
        Closure $write,
    ): void {
        $wrote = false;
        $seen = 0;

        $syncRepl->listen(function (SyncEntryResult $entry, Session $session) use (&$wrote, &$seen, $write): void {
            $refreshing = !$session->isRefreshComplete();
            if ($refreshing && !$wrote) {
                $wrote = true;
                $this->onAnotherConnection($write);

                return;
            }
            if ($refreshing) {
                return;
            }
            $seen++;

            if ($seen >= self::MAX_PERSIST_RESULTS) {
                throw new CancelRequestException();
            }
        });
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
                ->setPort(TestWorker::port())
                ->setTransport('tcp')
                ->setServers(['127.0.0.1'])
                ->setSslValidateCert(false)
                ->setTimeoutRead(self::LISTEN_READ_TIMEOUT),
        );
    }
}
