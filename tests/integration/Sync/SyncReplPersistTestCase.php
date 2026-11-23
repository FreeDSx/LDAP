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
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\CancelRequestException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\IntermediateResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Session;
use FreeDSx\Ldap\Sync\SyncRepl;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;
use Tests\Support\FreeDSx\Ldap\Sync\PersistDeletionLog;
use Tests\Support\FreeDSx\Ldap\TestWorker;

/**
 * Shared end-to-end RFC 4533 refreshAndPersist coverage.
 */
abstract class SyncReplPersistTestCase extends ServerTestCase
{
    use RawClientQueueTrait;

    protected const SEED_LDIF = __DIR__ . '/../../resources/seed/sync-seed.ldif';

    private const LISTEN_READ_TIMEOUT = 20;

    /**
     * The provider keepalives every poll, so a read never idles out; this bounds the wait for an expected result.
     */
    private const MAX_PERSIST_RESULTS = 5;

    private const IDSET_CONTAINER = 'ou=idset,dc=foo,dc=bar';

    /**
     * The first cookie change after this entry's add means every deletion journaled before it was sent.
     */
    private const IDSET_MARKER = 'cn=idset-marker,dc=foo,dc=bar';

    /**
     * The marker and a deletion for each entry, with room to spare before giving up.
     */
    private const MAX_IDSET_PERSIST_RESULTS = 20;

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

    public function testASecondCancelForAPersistSearchIsAnswered(): void
    {
        $queue = $this->rawQueue(timeoutRead: 5);

        try {
            $queue->sendMessage(new LdapMessageRequest(
                1,
                Operations::bind(
                    'cn=user,dc=foo,dc=bar',
                    '12345',
                ),
            ));
            $queue->getMessage(1);

            $queue->sendMessage(new LdapMessageRequest(
                2,
                Operations::search(Filters::present('objectClass'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
                new SyncRequestControl(SyncRequestControl::MODE_REFRESH_AND_PERSIST),
            ));
            do {
                $message = $queue->getMessage(2);
            } while (!$message->getResponse() instanceof IntermediateResponse);

            $queue->sendMessage(
                new LdapMessageRequest(
                    3,
                    Operations::cancel(2),
                ),
                new LdapMessageRequest(
                    4,
                    Operations::cancel(2),
                ),
            );

            self::assertSame(
                [
                    3 => ResultCode::SUCCESS,
                    4 => ResultCode::NO_SUCH_OPERATION,
                ],
                $this->resultCodesFor(
                    $queue,
                    3,
                    4,
                ),
            );
        } finally {
            $queue->close();
        }
    }

    public function testRequestsSentDuringAPersistSearchAreRefusedWithAnOperationsError(): void
    {
        $queue = $this->rawQueue(timeoutRead: 5);

        try {
            $queue->sendMessage(new LdapMessageRequest(
                1,
                Operations::bind(
                    'cn=user,dc=foo,dc=bar',
                    '12345',
                ),
            ));
            $queue->getMessage(1);

            $queue->sendMessage(new LdapMessageRequest(
                2,
                Operations::search(Filters::present('objectClass'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
                new SyncRequestControl(SyncRequestControl::MODE_REFRESH_AND_PERSIST),
            ));
            do {
                $message = $queue->getMessage(2);
            } while (!$message->getResponse() instanceof IntermediateResponse);

            $queue->sendMessage(
                new LdapMessageRequest(
                    3,
                    Operations::whoami(),
                ),
                new LdapMessageRequest(
                    4,
                    new ExtendedRequest(ExtendedRequest::OID_START_TLS),
                ),
                new LdapMessageRequest(
                    5,
                    Operations::bind(
                        'cn=user,dc=foo,dc=bar',
                        '12345',
                    ),
                ),
            );

            self::assertSame(
                [
                    3 => ResultCode::OPERATIONS_ERROR,
                    4 => ResultCode::OPERATIONS_ERROR,
                    5 => ResultCode::OPERATIONS_ERROR,
                ],
                $this->resultCodesFor(
                    $queue,
                    3,
                    4,
                    5,
                ),
            );

            $queue->sendMessage(new LdapMessageRequest(
                6,
                Operations::cancel(2),
            ));

            self::assertSame(
                [
                    2 => ResultCode::CANCELED,
                    6 => ResultCode::SUCCESS,
                ],
                $this->resultCodesFor(
                    $queue,
                    2,
                    6,
                ),
            );

            $queue->sendMessage(new LdapMessageRequest(
                7,
                Operations::whoami(),
            ));

            self::assertSame(
                [7 => ResultCode::SUCCESS],
                $this->resultCodesFor(
                    $queue,
                    7,
                ),
            );
        } finally {
            $queue->close();
        }
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

    public function testPersistDeliversAModifyForAnEntryThatStillMatchesAMemberOfFilter(): void
    {
        $member = 'cn=persist-member,dc=foo,dc=bar';
        $group = 'cn=persist-group,dc=foo,dc=bar';
        $result = null;
        $wrote = false;

        $this->onAnotherConnection(static function (LdapClient $w) use ($member, $group): void {
            $w->create(Entry::fromArray(
                $member,
                [
                    'cn' => 'persist-member',
                    'sn' => 'Member',
                    'objectClass' => 'inetOrgPerson',
                ],
            ));
            $w->create(Entry::fromArray(
                $group,
                [
                    'cn' => 'persist-group',
                    'member' => $member,
                    'objectClass' => 'groupOfNames',
                ],
            ));
        });

        $syncRepl = $this->boundSync(Filters::equal(
            'memberOf',
            $group,
        ));

        $syncRepl->listen(function (SyncEntryResult $entry, Session $session) use (&$result, &$wrote, $member): void {
            if (!$session->isRefreshComplete()) {
                if (!$wrote) {
                    $wrote = true;
                    $this->onAnotherConnection(fn(LdapClient $w) => $w->sendAndReceive(Operations::modify(
                        $member,
                        Change::replace(
                            'description',
                            'changed',
                        ),
                    )));
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
            $result->isModify(),
            'A change that leaves the entry in the group is delivered as a modify, not a delete.',
        );
        self::assertSame(
            $member,
            strtolower($result->getEntry()->getDn()->toString()),
        );
    }

    /**
     * RFC 4533 §3.4.2 asks for multiple delete entries to be coalesced into a syncIdSet.
     */
    public function testPersistCoalescesMultipleDeletionsIntoAnIdSet(): void
    {
        $log = new PersistDeletionLog(self::IDSET_MARKER);
        $wrote = false;
        $seen = 0;
        $this->onAnotherConnection(fn(LdapClient $writer) => $log->useNames($this->createASubtree($writer)));

        $syncRepl = $this->boundSync();
        $syncRepl->useIdSetHandler($log->recordSet(...));
        $syncRepl->useCookieHandler(static function () use ($log): void {
            if ($log->isMarked()) {
                throw new CancelRequestException();
            }
        });

        $syncRepl->listen(function (SyncEntryResult $entry, Session $session) use ($log, &$wrote, &$seen): void {
            if (!$session->isRefreshComplete()) {
                if (!$wrote) {
                    $wrote = true;
                    $this->onAnotherConnection($this->subtreeDeleteThenMarkIt(...));
                }

                return;
            }

            $log->recordEntry($entry);
            if (++$seen >= self::MAX_IDSET_PERSIST_RESULTS) {
                throw new CancelRequestException();
            }
        });
        $this->onAnotherConnection(static fn(LdapClient $w) => $w->delete(self::IDSET_MARKER));

        self::assertEqualsCanonicalizing(
            $log->expectedNames(),
            $log->deletedNames(),
            'Every removed entry is reported deleted. ' . $log->summary(),
        );
        self::assertInstanceOf(
            SyncIdSetResult::class,
            $log->firstSet(),
            'Several deletions in one journal window are delivered as a single syncIdSet. ' . $log->summary(),
        );
        self::assertTrue($log->firstSet()->isDeleted());
        self::assertCount(
            4,
            $log->firstSet(),
            $log->summary(),
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

    protected function boundSync(?FilterInterface $filter = null): SyncRepl
    {
        $client = $this->listenClient();
        $client->bind('cn=user,dc=foo,dc=bar', '12345');

        $syncRepl = $client->syncRepl($filter);
        $syncRepl->request()
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        return $syncRepl;
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

    /**
     * Written before the listen, keeping the adds whose fetch could race the delete out of the persist window.
     *
     * @return array<string, string> each entry's name, by its entryUUID
     */
    private function createASubtree(LdapClient $writer): array
    {
        $writer->create(Entry::fromArray(
            self::IDSET_CONTAINER,
            [
                'ou' => 'idset',
                'objectClass' => 'organizationalUnit',
            ],
        ));
        $names = [
            $this->uuidOf(
                $writer,
                self::IDSET_CONTAINER,
            ) => 'ou=idset',
        ];

        foreach (['idset-one', 'idset-two', 'idset-three'] as $cn) {
            $dn = 'cn=' . $cn . ',' . self::IDSET_CONTAINER;
            $writer->create(Entry::fromArray(
                $dn,
                [
                    'cn' => $cn,
                    'sn' => 'Doomed',
                    'objectClass' => 'inetOrgPerson',
                ],
            ));
            $names[$this->uuidOf(
                $writer,
                $dn,
            )] = 'cn=' . $cn;
        }

        return $names;
    }

    /**
     * Removes the container and its three children with one subtree delete, then writes the marker.
     */
    private function subtreeDeleteThenMarkIt(LdapClient $writer): void
    {
        // Separate deletes can straddle a journal poll, while a subtree delete commits them all together.
        $writer->sendAndReceive(
            Operations::delete(self::IDSET_CONTAINER),
            Controls::subtreeDelete(),
        );
        $writer->create(Entry::fromArray(
            self::IDSET_MARKER,
            [
                'cn' => 'idset-marker',
                'sn' => 'Marker',
                'objectClass' => 'inetOrgPerson',
            ],
        ));
    }

    private function uuidOf(
        LdapClient $client,
        string $dn,
    ): string {
        return (string) $client->read(
            $dn,
            ['entryUUID'],
        )?->get('entryUUID')?->firstValue();
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
