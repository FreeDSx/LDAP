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

namespace Tests\Unit\FreeDSx\Ldap\Sync\Provider;

use Closure;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncNewCookie;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\Cancellation;
use FreeDSx\Ldap\Protocol\Queue\Response\QueueWriterConfig;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseWriter;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeStream;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\Sync\Provider\SyncPersistStreamer;
use FreeDSx\Ldap\Sync\Provider\SyncResultProjector;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Clock\CallbackSleeper;

final class SyncPersistStreamerTest extends TestCase
{
    private const ORIGIN = 'test-origin';

    private const ENTRY_DN = 'cn=new,dc=example,dc=com';

    private const ENTRY_UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

    private ServerQueue&MockObject $queue;

    private ReadBackendInterface&MockObject $backend;

    private TokenInterface&MockObject $token;

    private InMemoryChangeJournal $journal;

    private SyncPersistStreamer $subject;

    /**
     * @var list<LdapMessageResponse>
     */
    private array $sent = [];

    /**
     * @var list<?LdapMessageRequest>
     */
    private array $cancelSignals = [];

    /**
     * @var array<string, Entry>
     */
    private array $liveEntries = [];

    private Closure $onSleep;

    protected function setUp(): void
    {
        $this->onSleep = static function (): void {};
        $this->journal = new InMemoryChangeJournal(new ReplicaId(self::ORIGIN));
        $this->token = $this->createMock(TokenInterface::class);

        $this->queue = $this->createMock(ServerQueue::class);
        $this->queue
            ->method('sendMessages')
            ->willReturnCallback(function (iterable $responses): ServerQueue {
                foreach ($responses as $response) {
                    if (!$response instanceof LdapMessageResponse) {
                        continue;
                    }

                    $this->sent[] = $response;
                }

                return $this->queue;
            });
        $this->queue
            ->method('peekForCancelSignal')
            ->willReturnCallback(fn(): ?LdapMessageRequest => array_shift($this->cancelSignals));

        $this->backend = $this->createMock(ReadBackendInterface::class);
        $this->backend
            ->method('get')
            ->willReturnCallback(fn(Dn $dn): ?Entry => $this->liveEntries[$dn->toString()] ?? null);

        $accessControl = $this->createMock(AccessControlInterface::class);
        $accessControl
            ->method('isEntryVisible')
            ->willReturn(true);
        $filterEvaluator = $this->createMock(FilterEvaluatorInterface::class);
        $filterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $this->subject = new SyncPersistStreamer(
            backend: $this->backend,
            projector: new SyncResultProjector(
                accessControl: $accessControl,
                filterEvaluator: $filterEvaluator,
                schema: SchemaResource::Core->load(),
            ),
            stream: new ChangeStream($this->journal),
            sleeper: new CallbackSleeper(fn() => ($this->onSleep)()),
            pollInterval: 0.0,
        );
    }

    public function test_a_cancel_closes_the_stream_with_a_canceled_result_and_acknowledges_the_cancel(): void
    {
        $this->cancelSignals = [new LdapMessageRequest(9, new CancelRequest(5))];

        $this->drive($this->subject);

        $done = $this->firstSent(fn(LdapMessageResponse $m): bool => $m->getResponse() instanceof SearchResultDone);
        self::assertNotNull($done);
        $response = $done->getResponse();
        self::assertInstanceOf(SearchResultDone::class, $response);
        self::assertSame(
            ResultCode::CANCELED,
            $response->getResultCode(),
        );
        self::assertSame(
            5,
            $done->getMessageId(),
        );
        self::assertNotNull($done->controls()->getByClass(SyncDoneControl::class));

        $ack = $this->firstSent(fn(LdapMessageResponse $m): bool => $m->getMessageId() === 9);
        self::assertNotNull($ack);
    }

    public function test_an_abandon_closes_the_stream_without_any_response(): void
    {
        $this->cancelSignals = [new LdapMessageRequest(9, new AbandonRequest(5))];

        $this->drive($this->subject);

        self::assertNull(
            $this->firstSent(fn(LdapMessageResponse $m): bool => $m->getResponse() instanceof SearchResultDone),
            'An abandon must not produce a SearchResultDone.',
        );
        self::assertNotNull(
            $this->firstSent(fn(LdapMessageResponse $m): bool => $m->getResponse() instanceof SyncNewCookie),
        );
    }

    public function test_a_change_that_lands_during_the_loop_is_pushed_as_an_add(): void
    {
        $this->liveEntries[self::ENTRY_DN] = $this->entry();
        $this->onSleep = function (): void {
            $this->append(ChangeType::Add);
            $this->cancelSignals[] = new LdapMessageRequest(9, new CancelRequest(5));
        };

        $this->drive($this->subject);

        $entry = $this->firstSent(fn(LdapMessageResponse $m): bool => $m->getResponse() instanceof SearchResultEntry);
        self::assertNotNull($entry);
        $response = $entry->getResponse();
        self::assertInstanceOf(SearchResultEntry::class, $response);
        self::assertSame(
            self::ENTRY_DN,
            $response->getEntry()->getDn()->toString(),
        );
        $state = $entry->controls()->getByClass(SyncStateControl::class);
        self::assertNotNull($state);
        self::assertSame(
            SyncStateControl::STATE_ADD,
            $state->getState(),
        );
    }

    public function test_a_trim_past_the_consumer_position_ends_with_refresh_required(): void
    {
        $journal = $this->createMock(ChangeJournalInterface::class);
        $journal
            ->method('latestSeq')
            ->willReturn(5);
        $journal
            ->method('retainsSince')
            ->willReturn(false);
        $journal
            ->method('origin')
            ->willReturn(new ReplicaId(self::ORIGIN));

        $subject = new SyncPersistStreamer(
            backend: $this->backend,
            projector: new SyncResultProjector(
                accessControl: $this->createMock(AccessControlInterface::class),
                filterEvaluator: $this->createMock(FilterEvaluatorInterface::class),
                schema: SchemaResource::Core->load(),
            ),
            stream: new ChangeStream($journal),
            sleeper: new CallbackSleeper(),
            pollInterval: 0.0,
        );

        $this->drive($subject);

        $done = $this->firstSent(fn(LdapMessageResponse $m): bool => $m->getResponse() instanceof SearchResultDone);
        self::assertNotNull($done);
        $response = $done->getResponse();
        self::assertInstanceOf(SearchResultDone::class, $response);
        self::assertSame(
            ResultCode::SYNCHRONIZATION_REFRESH_REQUIRED,
            $response->getResultCode(),
        );
    }

    /**
     * Drives the persist generator through the writer, which polls the queue and feeds the cancellation token.
     */
    private function drive(SyncPersistStreamer $subject): void
    {
        $cancellation = new Cancellation();
        $stream = ResponseStream::streaming(
            $subject->stream(
                0,
                $this->request(),
                $this->token,
                5,
                $cancellation,
            ),
            fn(): OperationOutcomeResult => OperationOutcomeResult::succeeded(),
            new QueueWriterConfig(flushPerMessage: true, signalInterval: 1),
            $cancellation,
        );

        (new ResponseWriter($this->queue))->write(
            $stream,
            5,
        );
    }

    private function request(): SearchRequest
    {
        return (new SearchRequest(Filters::present('objectClass')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
    }

    private function firstSent(callable $predicate): ?LdapMessageResponse
    {
        foreach ($this->sent as $message) {
            if ($predicate($message)) {
                return $message;
            }
        }

        return null;
    }

    private function append(ChangeType $type): void
    {
        $this->journal->append(new PendingChange(
            changeType: $type,
            dn: new Dn(self::ENTRY_DN),
            entryUuid: self::ENTRY_UUID,
            authzId: AuthzId::anonymous(),
        ));
    }

    private function entry(): Entry
    {
        return Entry::create(
            self::ENTRY_DN,
            [
                'objectClass' => 'inetOrgPerson',
                'cn' => 'new',
                'entryUUID' => self::ENTRY_UUID,
            ],
        );
    }
}
