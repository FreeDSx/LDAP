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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshPresent;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseWriter;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerSyncHandler;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\FetchedBatch;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeStream;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionPolicy;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Sync\Provider\SyncCookie;
use FreeDSx\Ldap\Sync\Provider\SyncPersistStreamer;
use FreeDSx\Ldap\Sync\Provider\SyncResultProjector;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerSyncHandlerTest extends TestCase
{
    private const ORIGIN = 'test-origin';

    private const UUID_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

    private const UUID_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

    private ServerQueue&MockObject $queue;

    private LdapBackendInterface&MockObject $backend;

    private FilterEvaluatorInterface&MockObject $filterEvaluator;

    private AccessControlInterface&MockObject $accessControl;

    private TokenInterface&MockObject $token;

    private InMemoryChangeJournal $journal;

    private ChangeStream $changeStream;

    private SyncResultProjector $syncProjector;

    private SyncPersistStreamer $persistStreamer;

    private ServerSyncHandler $subject;

    /**
     * @var list<?LdapMessageRequest> cancel/abandon signals the persist loop peeks, in order
     */
    private array $cancelSignals = [];

    /**
     * @var list<LdapMessageResponse>
     */
    private array $sent = [];

    /**
     * @var list<string> DNs the ACL hides from the consumer
     */
    private array $hiddenDns = [];

    private bool $filterMatches = true;

    /**
     * @var array<string, Entry> live entries returned by backend::get(), keyed by DN
     */
    private array $liveEntries = [];

    /**
     * @var list<Entry> entries returned by backend::search() for a full refresh
     */
    private array $searchEntries = [];

    protected function setUp(): void
    {
        $this->queue = $this->createMock(ServerQueue::class);
        $this->backend = $this->createMock(LdapBackendInterface::class);
        $this->filterEvaluator = $this->createMock(FilterEvaluatorInterface::class);
        $this->accessControl = $this->createMock(AccessControlInterface::class);
        $this->token = $this->createMock(TokenInterface::class);
        $this->journal = new InMemoryChangeJournal(new ReplicaId(self::ORIGIN));

        $this->accessControl
            ->method('isEntryVisible')
            ->willReturnCallback(fn(TokenInterface $token, Entry $entry): bool => !in_array(
                $entry->getDn()->toString(),
                $this->hiddenDns,
                true,
            ));
        $this->filterEvaluator
            ->method('evaluate')
            ->willReturnCallback(fn(): bool => $this->filterMatches);
        $this->backend
            ->method('search')
            ->willReturnCallback(fn(): EntryStream => new EntryStream($this->stream(...$this->searchEntries)));
        $this->backend
            ->method('get')
            ->willReturnCallback(fn(Dn $dn): ?Entry => $this->liveEntries[$dn->toString()] ?? null);
        $this->queue
            ->method('sendMessages')
            ->willReturnCallback(function (iterable $messages): ServerQueue {
                foreach ($messages as $message) {
                    if (!$message instanceof LdapMessageResponse) {
                        continue;
                    }

                    $this->sent[] = $message;
                }

                return $this->queue;
            });
        $this->queue
            ->method('peekForCancelSignal')
            ->willReturnCallback(fn(): ?LdapMessageRequest => array_shift($this->cancelSignals));

        $this->changeStream = new ChangeStream($this->journal);
        $this->syncProjector = new SyncResultProjector(
            accessControl: $this->accessControl,
            filterEvaluator: $this->filterEvaluator,
            schema: SchemaResource::Core->load(),
        );
        $this->persistStreamer = new SyncPersistStreamer(
            backend: $this->backend,
            projector: $this->syncProjector,
            stream: $this->changeStream,
            sleeper: new BlockingSleeper(),
        );

        $this->subject = new ServerSyncHandler(
            backend: $this->backend,
            projector: $this->syncProjector,
            changeStream: $this->changeStream,
            persistStreamer: $this->persistStreamer,
        );
    }

    public function test_an_empty_cookie_streams_all_live_entries_as_add(): void
    {
        $this->append(ChangeType::Add, 'cn=a,dc=example,dc=com', self::UUID_A);
        $this->searchEntries = [
            $this->entry('cn=a,dc=example,dc=com', self::UUID_A),
            $this->entry('cn=b,dc=example,dc=com', self::UUID_B),
        ];

        $result = $this->handle(null);

        self::assertSame(
            OperationOutcome::Succeeded,
            $result->outcome(),
        );
        self::assertSame(
            [
                [SyncStateControl::STATE_ADD, self::UUID_A],
                [SyncStateControl::STATE_ADD, self::UUID_B],
            ],
            $this->states(),
        );
        self::assertSame(
            1,
            $this->doneCookie()->seq,
        );
    }

    public function test_the_done_cookie_carries_the_origin(): void
    {
        $this->handle(null);

        self::assertTrue($this->doneCookie()->origin->equals(new ReplicaId(self::ORIGIN)));
    }

    public function test_a_full_refresh_is_a_present_phase(): void
    {
        $this->handle(null);

        self::assertFalse($this->doneControl()->getRefreshDeletes());
    }

    public function test_an_incremental_sync_is_a_delete_phase(): void
    {
        $this->append(ChangeType::Modify, 'cn=a,dc=example,dc=com', self::UUID_A);
        $this->liveEntries['cn=a,dc=example,dc=com'] = $this->entry('cn=a,dc=example,dc=com', self::UUID_A);

        $this->handle($this->cookieAt(0));

        self::assertTrue($this->doneControl()->getRefreshDeletes());
    }

    public function test_an_acl_hidden_entry_is_omitted_from_a_full_refresh(): void
    {
        $this->searchEntries = [
            $this->entry('cn=a,dc=example,dc=com', self::UUID_A),
            $this->entry('cn=b,dc=example,dc=com', self::UUID_B),
        ];
        $this->hiddenDns = ['cn=b,dc=example,dc=com'];

        $this->handle(null);

        self::assertSame(
            [[SyncStateControl::STATE_ADD, self::UUID_A]],
            $this->states(),
        );
    }

    public function test_an_entry_without_a_uuid_is_skipped(): void
    {
        $this->searchEntries = [Entry::create('cn=a,dc=example,dc=com', ['cn' => 'a'])];

        $this->handle(null);

        self::assertSame(
            [],
            $this->states(),
        );
    }

    #[DataProvider('fullRefreshTriggers')]
    public function test_an_unusable_cookie_falls_back_to_a_full_refresh(string $cookie, bool $reloadHint): void
    {
        // A journal record that would surface under an incremental sync, so its absence proves a full refresh.
        $this->append(ChangeType::Modify, 'cn=b,dc=example,dc=com', self::UUID_B);
        $this->searchEntries = [$this->entry('cn=a,dc=example,dc=com', self::UUID_A)];

        $this->handle($cookie, reloadHint: $reloadHint);

        self::assertSame(
            [[SyncStateControl::STATE_ADD, self::UUID_A]],
            $this->states(),
        );
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function fullRefreshTriggers(): iterable
    {
        $content = SyncCookie::contentKey(self::searchRequest());

        yield 'malformed cookie' => [
            '@@not a cookie@@',
            false,
        ];
        yield 'cookie from another origin' => [
            (new SyncCookie(new ReplicaId('other'), 0, $content))->encode(),
            false,
        ];
        yield 'reload hint set' => [
            (new SyncCookie(new ReplicaId(self::ORIGIN), 0, $content))->encode(),
            true,
        ];
        yield 'cookie issued for different content' => [
            (new SyncCookie(
                new ReplicaId(self::ORIGIN),
                0,
                SyncCookie::contentKey(self::searchRequest()->select('cn')),
            ))->encode(),
            false,
        ];
    }

    public function test_a_valid_cookie_streams_the_delta_as_modifies_and_deletes(): void
    {
        $this->append(ChangeType::Modify, 'cn=a,dc=example,dc=com', self::UUID_A);
        $this->append(
            ChangeType::Delete,
            'cn=b,dc=example,dc=com',
            self::UUID_B,
            $this->entry('cn=b,dc=example,dc=com', self::UUID_B),
        );
        $this->liveEntries['cn=a,dc=example,dc=com'] = $this->entry('cn=a,dc=example,dc=com', self::UUID_A);

        $this->handle($this->cookieAt(0));

        self::assertSame(
            [
                [SyncStateControl::STATE_MODIFY, self::UUID_A],
                [SyncStateControl::STATE_DELETE, self::UUID_B],
            ],
            $this->states(),
        );
        self::assertSame(
            2,
            $this->doneCookie()->seq,
        );
    }

    public function test_repeated_changes_to_one_entry_collapse_to_the_net_effect(): void
    {
        $this->append(ChangeType::Add, 'cn=a,dc=example,dc=com', self::UUID_A);
        $this->append(
            ChangeType::Delete,
            'cn=a,dc=example,dc=com',
            self::UUID_A,
            $this->entry('cn=a,dc=example,dc=com', self::UUID_A),
        );

        $this->handle($this->cookieAt(0));

        self::assertSame(
            [[SyncStateControl::STATE_DELETE, self::UUID_A]],
            $this->states(),
        );
    }

    public function test_a_changed_entry_that_no_longer_matches_the_filter_is_announced_as_a_delete(): void
    {
        $this->append(ChangeType::Modify, 'cn=a,dc=example,dc=com', self::UUID_A);
        $this->liveEntries['cn=a,dc=example,dc=com'] = $this->entry('cn=a,dc=example,dc=com', self::UUID_A);
        $this->filterMatches = false;

        $this->handle($this->cookieAt(0));

        self::assertSame(
            [[SyncStateControl::STATE_DELETE, self::UUID_A]],
            $this->states(),
        );
    }

    public function test_a_changed_entry_gone_since_the_change_is_skipped(): void
    {
        $this->append(ChangeType::Modify, 'cn=a,dc=example,dc=com', self::UUID_A);
        // No live entry registered: backend::get() returns null.

        $this->handle($this->cookieAt(0));

        self::assertSame(
            [],
            $this->states(),
        );
    }

    public function test_a_delete_is_not_announced_when_the_consumer_could_not_see_the_entry(): void
    {
        $this->append(
            ChangeType::Delete,
            'cn=secret,dc=example,dc=com',
            self::UUID_B,
            $this->entry('cn=secret,dc=example,dc=com', self::UUID_B),
        );
        $this->hiddenDns = ['cn=secret,dc=example,dc=com'];

        $this->handle($this->cookieAt(0));

        self::assertSame(
            [],
            $this->states(),
        );
    }

    public function test_a_delete_without_a_pre_image_is_not_announced(): void
    {
        $this->append(ChangeType::Delete, 'cn=b,dc=example,dc=com', self::UUID_B);

        $this->handle($this->cookieAt(0));

        self::assertSame(
            [],
            $this->states(),
        );
    }

    public function test_a_cookie_past_the_trim_horizon_gets_a_present_phase_full_refresh(): void
    {
        $this->append(ChangeType::Add, 'cn=a,dc=example,dc=com', self::UUID_A);
        $this->append(ChangeType::Add, 'cn=b,dc=example,dc=com', self::UUID_B);
        $this->append(ChangeType::Delete, 'cn=gone,dc=example,dc=com', self::UUID_A);
        $this->journal->prune(new RetentionPolicy(maxRecords: 1));
        $this->searchEntries = [
            $this->entry('cn=a,dc=example,dc=com', self::UUID_A),
            $this->entry('cn=b,dc=example,dc=com', self::UUID_B),
        ];

        // Cookie at seq 1 is below the retained floor (seq 3), so the incremental path would miss changes.
        $this->handle($this->cookieAt(1));

        self::assertSame(
            [
                [SyncStateControl::STATE_ADD, self::UUID_A],
                [SyncStateControl::STATE_ADD, self::UUID_B],
            ],
            $this->states(),
        );
        self::assertFalse($this->doneControl()->getRefreshDeletes());
    }

    public function test_a_full_refresh_skips_an_entry_with_a_malformed_uuid_without_aborting(): void
    {
        $this->searchEntries = [
            $this->entry('cn=bad,dc=example,dc=com', 'not-a-uuid'),
            $this->entry('cn=b,dc=example,dc=com', self::UUID_B),
        ];

        $this->handle(null);

        self::assertSame(
            [[SyncStateControl::STATE_ADD, self::UUID_B]],
            $this->states(),
        );
        self::assertFalse($this->doneControl()->getRefreshDeletes());
    }

    public function test_a_delete_with_a_malformed_uuid_is_skipped_without_aborting(): void
    {
        $this->append(
            ChangeType::Delete,
            'cn=bad,dc=example,dc=com',
            'not-a-uuid',
            $this->entry('cn=bad,dc=example,dc=com', 'not-a-uuid'),
        );

        $this->handle($this->cookieAt(0));

        self::assertSame(
            [],
            $this->states(),
        );
        self::assertTrue($this->doneControl()->getRefreshDeletes());
    }

    public function test_refresh_and_persist_is_declined_when_persist_is_unsupported(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->handle(null, mode: SyncRequestControl::MODE_REFRESH_AND_PERSIST);
    }

    public function test_refresh_and_persist_full_refresh_ends_the_refresh_phase_with_a_present_boundary(): void
    {
        $this->searchEntries = [$this->entry('cn=a,dc=example,dc=com', self::UUID_A)];
        // A pending cancel terminates the persist loop after the boundary is emitted.
        $this->cancelSignals = [new LdapMessageRequest(9, new CancelRequest(1))];

        $this->drive(
            $this->persistHandler(),
            $this->syncMessage(null, SyncRequestControl::MODE_REFRESH_AND_PERSIST),
        );

        $boundary = null;
        foreach ($this->sent as $message) {
            if ($message->getResponse() instanceof SyncRefreshPresent) {
                $boundary = $message->getResponse();

                break;
            }
        }

        self::assertInstanceOf(
            SyncRefreshPresent::class,
            $boundary,
        );
        self::assertTrue($boundary->getRefreshDone());
    }

    public function test_sync_is_declined_when_no_change_stream_is_available(): void
    {
        $handler = new ServerSyncHandler(
            backend: $this->backend,
            projector: new SyncResultProjector(
                accessControl: $this->accessControl,
                filterEvaluator: $this->filterEvaluator,
                schema: SchemaResource::Core->load(),
            ),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $handler->handleRequest(
            $this->syncMessage(null),
            $this->token,
        );
    }

    private function persistHandler(): ServerSyncHandler
    {
        return new ServerSyncHandler(
            backend: $this->backend,
            projector: $this->syncProjector,
            changeStream: $this->changeStream,
            persistStreamer: $this->persistStreamer,
            persistSupported: true,
        );
    }

    private function handle(
        ?string $cookie,
        int $mode = SyncRequestControl::MODE_REFRESH_ONLY,
        bool $reloadHint = false,
    ): OperationResult {
        return $this->drive(
            $this->subject,
            $this->syncMessage($cookie, $mode, $reloadHint),
        );
    }

    /**
     * Drives the handler's stream through the writer, which populates the queue and polls for cancellation.
     */
    private function drive(
        ServerSyncHandler $handler,
        LdapMessageRequest $message,
    ): OperationResult {
        return (new ResponseWriter($this->queue))->write(
            $handler->handleRequest(
                $message,
                $this->token,
            ),
            $message->getMessageId(),
        );
    }

    private static function searchRequest(): SearchRequest
    {
        return (new SearchRequest(Filters::present('objectClass')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
    }

    private function syncMessage(
        ?string $cookie,
        int $mode = SyncRequestControl::MODE_REFRESH_ONLY,
        bool $reloadHint = false,
    ): LdapMessageRequest {
        return new LdapMessageRequest(
            1,
            self::searchRequest(),
            new SyncRequestControl($mode, $cookie, $reloadHint),
        );
    }

    private function cookieAt(int $seq): string
    {
        return (new SyncCookie(
            new ReplicaId(self::ORIGIN),
            $seq,
            SyncCookie::contentKey(self::searchRequest()),
        ))->encode();
    }

    private function append(
        ChangeType $type,
        string $dn,
        string $uuid,
        ?Entry $preImage = null,
    ): void {
        $this->journal->append(new PendingChange(
            changeType: $type,
            dn: new Dn($dn),
            entryUuid: $uuid,
            authzId: AuthzId::anonymous(),
            preImage: $preImage,
        ));
    }

    private function entry(
        string $dn,
        string $uuid,
    ): Entry {
        return Entry::create(
            $dn,
            [
                'cn' => 'x',
                'entryUUID' => $uuid,
            ],
        );
    }

    /**
     * @return Generator<int, Entry, mixed, ?FetchedBatch>
     */
    private function stream(Entry ...$entries): Generator
    {
        foreach ($entries as $entry) {
            yield $entry;
        }

        return null;
    }

    /**
     * The (state, dashed-uuid) of every emitted SearchResultEntry, in order.
     *
     * @return list<array{int, string}>
     */
    private function states(): array
    {
        $states = [];

        foreach ($this->sent as $message) {
            if (!$message->getResponse() instanceof SearchResultEntry) {
                continue;
            }

            $control = $message->controls()->get(Control::OID_SYNC_STATE);
            self::assertInstanceOf(
                SyncStateControl::class,
                $control,
            );
            $states[] = [$control->getState(), $control->decodedUuid()];
        }

        return $states;
    }

    private function lastSent(): LdapMessageResponse
    {
        $last = end($this->sent);
        self::assertInstanceOf(
            LdapMessageResponse::class,
            $last,
        );

        return $last;
    }

    private function doneControl(): SyncDoneControl
    {
        $last = $this->lastSent();
        self::assertInstanceOf(
            SearchResultDone::class,
            $last->getResponse(),
        );

        $control = $last->controls()->get(Control::OID_SYNC_DONE);
        self::assertInstanceOf(
            SyncDoneControl::class,
            $control,
        );

        return $control;
    }

    private function doneCookie(): SyncCookie
    {
        return SyncCookie::decode((string) $this->doneControl()->getCookie());
    }
}
