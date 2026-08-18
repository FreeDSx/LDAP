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
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortingResponseControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseWriter;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPagingHandler;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\RequestHistory;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\Operation\SearchOperationResult;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use Generator;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class ServerPagingHandlerTest extends TestCase
{
    private RequestHistory $requestHistory;

    private ServerQueue&MockObject $mockQueue;

    private LdapBackendInterface&MockObject $mockBackend;

    private FilterEvaluatorInterface&MockObject $mockFilterEvaluator;

    private AccessControlInterface&MockObject $mockAccessControl;

    private ServerPagingHandler $subject;

    private TokenInterface&MockObject $mockToken;

    private Schema $schema;

    /**
     * @var list<LdapMessageResponse>
     */
    private array $sentMessages = [];

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockBackend = $this->createMock(LdapBackendInterface::class);
        $this->mockFilterEvaluator = $this->createMock(FilterEvaluatorInterface::class);
        $this->mockAccessControl = $this->createMock(AccessControlInterface::class);
        $this->requestHistory = new RequestHistory();
        $this->schema = SchemaResource::Core->load();
        $this->sentMessages = [];

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $this->mockAccessControl
            ->method('filterEntry')
            ->willReturnArgument(1);

        $this->mockQueue
            ->method('sendMessages')
            ->willReturnCallback(function (iterable $messages): ServerQueue {
                foreach ($messages as $message) {
                    if (!$message instanceof LdapMessageResponse) {
                        continue;
                    }

                    $this->sentMessages[] = $message;
                }

                return $this->mockQueue;
            });

        $this->subject = new ServerPagingHandler(
            backend: $this->mockBackend,
            filterEvaluator: $this->mockFilterEvaluator,
            accessControl: $this->mockAccessControl,
            requestHistory: $this->requestHistory,
            schema: $this->schema,
        );
    }

    public function test_it_should_call_the_backend_search_on_paging_start_and_return_entries(): void
    {
        $message = $this->makeSearchMessage(size: 10);

        $entry1 = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);
        $entry2 = Entry::create('dc=bar,dc=foo', ['cn' => 'bar']);

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->with(self::isInstanceOf(SearchRequest::class))
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2)));

        $result = $this->drive(
            $this->subject,
            $message,
        );

        self::assertEquals(
            [
                new LdapMessageResponse(2, new SearchResultEntry($entry1)),
                new LdapMessageResponse(2, new SearchResultEntry($entry2)),
            ],
            $this->entryMessages(),
        );
        // Generator was exhausted with only 2 entries, so paging is complete (cookie='').
        self::assertSame('', $this->donePagingControl()->getCookie());
        self::assertInstanceOf(SearchOperationResult::class, $result);
        self::assertSame(
            OperationOutcome::Succeeded,
            $result->outcome(),
        );
    }

    public function test_it_should_store_the_generator_and_return_a_cookie_when_more_entries_remain(): void
    {
        // Request only 1 entry, but backend yields 2, so generator is NOT exhausted.
        $message = $this->makeSearchMessage(size: 1);

        $entry1 = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);
        $entry2 = Entry::create('dc=bar,dc=foo', ['cn' => 'bar']);

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2)));

        $this->drive(
            $this->subject,
            $message,
        );

        self::assertEquals(
            [new LdapMessageResponse(2, new SearchResultEntry($entry1))],
            $this->entryMessages(),
        );
        // Non-empty cookie means more entries remain.
        self::assertNotSame('', $this->donePagingControl()->getCookie());
    }

    public function test_it_should_continue_from_the_stored_generator_on_subsequent_pages(): void
    {
        // First page: size=1 with 2 entries in the backend.
        $firstMessage = $this->makeSearchMessage(size: 1);

        $entry1 = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);
        $entry2 = Entry::create('dc=bar,dc=foo', ['cn' => 'bar']);

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2)));

        $this->drive($this->subject, $firstMessage);

        $capturedCookie = $this->donePagingControl()->getCookie();
        self::assertNotSame('', $capturedCookie);

        // Second page: use the captured cookie.
        $pagingReq = $this->requestHistory->pagingRequest()->findByNextCookie($capturedCookie);
        $secondMessage = $this->makeSearchMessage(
            size: 10,
            cookie: $capturedCookie,
            searchRequest: $pagingReq->getSearchRequest(),
        );

        $this->drive($this->subject, $secondMessage);
    }

    public function test_it_should_send_the_correct_response_if_paging_is_abandoned(): void
    {
        $pagingReq = $this->makeExistingPagingRequest();
        $message = $this->makeSearchMessage(
            size: 0,
            cookie: $pagingReq->getNextCookie(),
            searchRequest: $pagingReq->getSearchRequest(),
        );

        $this->mockBackend
            ->expects(self::never())
            ->method('search');

        $this->drive(
            $this->subject,
            $message,
        );

        self::assertSame([], $this->entryMessages());
        self::assertSame('', $this->donePagingControl()->getCookie());
    }

    public function test_it_sends_a_result_code_error_in_SearchResultDone_if_the_old_and_new_paging_requests_are_different(): void
    {
        $pagingReq = $this->makeExistingPagingRequest();
        $message = $this->makeSearchMessage(
            size: 10,
            cookie: $pagingReq->getNextCookie(),
            searchRequest: $this->makeSearchRequest('(oh=no)'),
        );

        $this->mockBackend
            ->expects(self::never())
            ->method('search');

        $this->drive(
            $this->subject,
            $message,
        );

        self::assertEquals(
            [
                new LdapMessageResponse(
                    $message->getMessageId(),
                    new SearchResultDone(
                        ResultCode::OPERATIONS_ERROR,
                        '',
                        "The search request and controls must be identical between paging requests.",
                    ),
                    new PagingControl(0, ''),
                ),
            ],
            $this->sentMessages,
        );
    }

    public function test_it_is_unwilling_to_perform_when_the_paging_generator_has_expired(): void
    {
        // A paging request exists and has been processed, but its generator was never stored
        // (simulating a session that expired or was evicted).
        $searchRequest = $this->makeSearchRequest();

        $pagingReq = new PagingRequest(
            new PagingControl(10, ''),
            $searchRequest,
            new ControlBag(),
            'expiredcookie',
        );
        $pagingReq->markProcessed();
        $this->requestHistory->pagingRequest()->add($pagingReq);

        $message = $this->makeSearchMessage(
            cookie: 'expiredcookie',
            searchRequest: $searchRequest,
        );

        $this->mockBackend
            ->expects(self::never())
            ->method('search');

        $result = $this->drive(
            $this->subject,
            $message,
        );

        self::assertSame([], $this->entryMessages());
        $done = $this->doneMessage()->getResponse();
        self::assertInstanceOf(SearchResultDone::class, $done);
        self::assertSame(ResultCode::UNWILLING_TO_PERFORM, $done->getResultCode());
        self::assertSame('', $this->donePagingControl()->getCookie());
        self::assertInstanceOf(SearchOperationResult::class, $result);
        self::assertSame(
            OperationOutcome::Failed,
            $result->outcome(),
        );
    }

    public function test_it_throws_an_exception_if_the_paging_cookie_does_not_exist(): void
    {
        $message = $this->makeSearchMessage(
            size: 10,
            cookie: 'nonexistent-cookie',
            searchRequest: $this->makeSearchRequest('(oh=no)'),
        );

        self::expectExceptionObject(new OperationException(
            'The supplied cookie is invalid.',
            ResultCode::UNWILLING_TO_PERFORM,
        ));

        $this->subject->handleRequest(
            $message,
            $this->mockToken,
        );
    }

    public function test_it_rejects_a_negative_page_size_on_the_initial_request(): void
    {
        $message = $this->makeSearchMessage(size: -1);

        $this->mockBackend
            ->expects(self::never())
            ->method('search');

        self::expectExceptionObject(new OperationException(
            'The paged results size must not be negative.',
            ResultCode::PROTOCOL_ERROR,
        ));

        $this->subject->handleRequest(
            $message,
            $this->mockToken,
        );
    }

    public function test_it_rejects_a_negative_page_size_on_a_subsequent_request(): void
    {
        $entry1 = Entry::create('cn=1,dc=foo,dc=bar', ['cn' => '1']);
        $entry2 = Entry::create('cn=2,dc=foo,dc=bar', ['cn' => '2']);
        $entry3 = Entry::create('cn=3,dc=foo,dc=bar', ['cn' => '3']);

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2, $entry3)));

        $subject = new ServerPagingHandler(
            backend: $this->mockBackend,
            filterEvaluator: $this->mockFilterEvaluator,
            accessControl: $this->mockAccessControl,
            requestHistory: $this->requestHistory,
            schema: $this->schema,
            limits: new SearchLimits(maxSearchPageSize: 1),
        );
        $this->drive($subject, $this->makeSearchMessage(size: 1));

        $cookie = $this->donePagingControl()->getCookie();
        self::assertNotSame('', $cookie);

        $this->sentMessages = [];
        $pagingReq = $this->requestHistory->pagingRequest()->findByNextCookie($cookie);

        try {
            $subject->handleRequest(
                $this->makeSearchMessage(
                    size: -1,
                    cookie: $cookie,
                    searchRequest: $pagingReq->getSearchRequest(),
                ),
                $this->mockToken,
            );
            self::fail('Expected the negative page size to be rejected.');
        } catch (OperationException $e) {
            self::assertSame(
                'The paged results size must not be negative.',
                $e->getMessage(),
            );
            self::assertSame(
                ResultCode::PROTOCOL_ERROR,
                $e->getCode(),
            );
        }

        // A negative size must not bypass the page bound and drain the rest of the result set.
        self::assertSame([], $this->entryMessages());
    }

    public function test_it_should_return_size_limit_exceeded_on_first_page_when_limit_is_hit(): void
    {
        $searchRequest = (new SearchRequest(Filters::raw('(foo=bar)')))
            ->base('dc=foo,dc=bar')
            ->sizeLimit(1);
        $message = $this->makeSearchMessage(size: 10, searchRequest: $searchRequest);

        $entry1 = Entry::create('cn=1,dc=foo,dc=bar', ['cn' => '1']);
        $entry2 = Entry::create('cn=2,dc=foo,dc=bar', ['cn' => '2']);

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2)));

        $this->drive($this->subject, $message);

        self::assertEquals(
            [new LdapMessageResponse(2, new SearchResultEntry($entry1))],
            $this->entryMessages(),
        );

        $done = $this->doneMessage()->getResponse();
        self::assertInstanceOf(SearchResultDone::class, $done);
        self::assertSame(ResultCode::SIZE_LIMIT_EXCEEDED, $done->getResultCode());
        self::assertSame('', $this->donePagingControl()->getCookie());
    }

    public function test_size_limit_applies_per_page_not_cumulatively(): void
    {
        $searchRequest = (new SearchRequest(Filters::raw('(foo=bar)')))
            ->base('dc=foo,dc=bar')
            ->sizeLimit(2);

        $entry1 = Entry::create('cn=1,dc=foo,dc=bar', ['cn' => '1']);
        $entry2 = Entry::create('cn=2,dc=foo,dc=bar', ['cn' => '2']);
        $entry3 = Entry::create('cn=3,dc=foo,dc=bar', ['cn' => '3']);
        $entry4 = Entry::create('cn=4,dc=foo,dc=bar', ['cn' => '4']);

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2, $entry3, $entry4)));

        // First page: pageSize=1, sizeLimit=2 — gets entry1, stores generator
        $this->drive(
            $this->subject,
            $this->makeSearchMessage(size: 1, searchRequest: $searchRequest),
        );

        $capturedCookie = $this->donePagingControl()->getCookie();
        self::assertNotSame('', $capturedCookie, 'Expected a non-empty cookie after the first page.');

        // Second page: pageSize=10, sizeLimit=2 — gets entry2+entry3 (hits limit), entry4 still in generator → SIZE_LIMIT_EXCEEDED
        $pagingReq = $this->requestHistory->pagingRequest()->findByNextCookie($capturedCookie);
        $this->drive(
            $this->subject,
            $this->makeSearchMessage(size: 10, cookie: $capturedCookie, searchRequest: $pagingReq->getSearchRequest()),
        );

        $sizeLimitExceededSeen = false;
        foreach ($this->sentMessages as $message) {
            $done = $message->getResponse();
            if ($done instanceof SearchResultDone && $done->getResultCode() === ResultCode::SIZE_LIMIT_EXCEEDED) {
                $sizeLimitExceededSeen = true;

                break;
            }
        }

        self::assertTrue($sizeLimitExceededSeen, 'Expected SIZE_LIMIT_EXCEEDED on the second page.');
    }

    public function test_server_max_search_size_applies_to_paged_search_when_client_requests_no_limit(): void
    {
        $searchRequest = (new SearchRequest(Filters::raw('(foo=bar)')))
            ->base('dc=foo,dc=bar')
            ->sizeLimit(0);
        $message = $this->makeSearchMessage(size: 10, searchRequest: $searchRequest);

        $entry1 = Entry::create('cn=1,dc=foo,dc=bar', ['cn' => '1']);
        $entry2 = Entry::create('cn=2,dc=foo,dc=bar', ['cn' => '2']);

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2)));

        $subject = new ServerPagingHandler(
            backend: $this->mockBackend,
            filterEvaluator: $this->mockFilterEvaluator,
            accessControl: $this->mockAccessControl,
            requestHistory: $this->requestHistory,
            schema: $this->schema,
            limits: new SearchLimits(maxSearchSize: 1),
        );
        $this->drive($subject, $message);

        self::assertEquals(
            [new LdapMessageResponse(2, new SearchResultEntry($entry1))],
            $this->entryMessages(),
        );

        $done = $this->doneMessage()->getResponse();
        self::assertInstanceOf(SearchResultDone::class, $done);
        self::assertSame(ResultCode::SIZE_LIMIT_EXCEEDED, $done->getResultCode());
    }

    public function test_starting_a_session_at_the_limit_evicts_the_least_recent(): void
    {
        $this->mockBackend
            ->method('search')
            ->willReturnCallback(fn(): EntryStream => new EntryStream($this->makeGenerator(
                Entry::create('cn=1,dc=foo,dc=bar', ['cn' => '1']),
                Entry::create('cn=2,dc=foo,dc=bar', ['cn' => '2']),
            )));

        $subject = new ServerPagingHandler(
            backend: $this->mockBackend,
            filterEvaluator: $this->mockFilterEvaluator,
            accessControl: $this->mockAccessControl,
            requestHistory: $this->requestHistory,
            schema: $this->schema,
            limits: new SearchLimits(maxPagingSessions: 2),
        );

        // Each leaves a page outstanding, so none of them completes and releases its slot.
        $this->drive($subject, $this->makeSearchMessage(size: 1));
        $firstCookie = $this->donePagingControl()->getCookie();
        $this->drive($subject, $this->makeSearchMessage(size: 1));
        $this->drive($subject, $this->makeSearchMessage(size: 1));

        self::assertSame(
            2,
            $this->requestHistory->pagingRequest()->count(),
        );
        self::assertNull(
            $this->requestHistory->getPagingGenerator($firstCookie),
            'The evicted session must not keep its generator alive.',
        );
        self::assertFalse(
            $this->requestHistory->pagingRequest()->has($firstCookie),
            'Resuming an evicted session must be refused.',
        );
    }

    public function test_a_session_that_runs_to_completion_releases_its_slot(): void
    {
        $this->mockBackend
            ->method('search')
            ->willReturnCallback(fn(): EntryStream => new EntryStream($this->makeGenerator(
                Entry::create('cn=1,dc=foo,dc=bar', ['cn' => '1']),
            )));

        $subject = new ServerPagingHandler(
            backend: $this->mockBackend,
            filterEvaluator: $this->mockFilterEvaluator,
            accessControl: $this->mockAccessControl,
            requestHistory: $this->requestHistory,
            schema: $this->schema,
            limits: new SearchLimits(maxPagingSessions: 2),
        );

        // A page larger than the result set finishes the search outright.
        $this->drive($subject, $this->makeSearchMessage(size: 10));
        $this->drive($subject, $this->makeSearchMessage(size: 10));
        $this->drive($subject, $this->makeSearchMessage(size: 10));

        self::assertSame(
            0,
            $this->requestHistory->pagingRequest()->count(),
            'Completed sessions must be reclaimed without waiting for eviction.',
        );
    }

    public function test_an_abandoned_session_releases_its_slot(): void
    {
        $this->mockBackend
            ->method('search')
            ->willReturnCallback(fn(): EntryStream => new EntryStream($this->makeGenerator(
                Entry::create('cn=1,dc=foo,dc=bar', ['cn' => '1']),
                Entry::create('cn=2,dc=foo,dc=bar', ['cn' => '2']),
            )));

        $subject = new ServerPagingHandler(
            backend: $this->mockBackend,
            filterEvaluator: $this->mockFilterEvaluator,
            accessControl: $this->mockAccessControl,
            requestHistory: $this->requestHistory,
            schema: $this->schema,
            limits: new SearchLimits(maxPagingSessions: 2),
        );

        $this->drive($subject, $this->makeSearchMessage(size: 1));
        $cookie = $this->donePagingControl()->getCookie();

        // RFC 2696 section 3: a zero page size with the cookie abandons the search.
        $this->drive($subject, $this->makeSearchMessage(size: 0, cookie: $cookie));

        self::assertSame(
            0,
            $this->requestHistory->pagingRequest()->count(),
        );
        self::assertNull($this->requestHistory->getPagingGenerator($cookie));
    }

    public function test_sessions_are_not_evicted_when_no_limit_is_set(): void
    {
        $this->mockBackend
            ->method('search')
            ->willReturnCallback(fn(): EntryStream => new EntryStream($this->makeGenerator(
                Entry::create('cn=1,dc=foo,dc=bar', ['cn' => '1']),
                Entry::create('cn=2,dc=foo,dc=bar', ['cn' => '2']),
            )));

        $subject = new ServerPagingHandler(
            backend: $this->mockBackend,
            filterEvaluator: $this->mockFilterEvaluator,
            accessControl: $this->mockAccessControl,
            requestHistory: $this->requestHistory,
            schema: $this->schema,
            limits: new SearchLimits(maxPagingSessions: 0),
        );

        $this->drive($subject, $this->makeSearchMessage(size: 1));
        $this->drive($subject, $this->makeSearchMessage(size: 1));
        $this->drive($subject, $this->makeSearchMessage(size: 1));

        self::assertSame(
            3,
            $this->requestHistory->pagingRequest()->count(),
        );
    }

    public function test_server_max_page_size_caps_client_page_size(): void
    {
        $message = $this->makeSearchMessage(size: 10);

        $entry1 = Entry::create('cn=1,dc=foo,dc=bar', ['cn' => '1']);
        $entry2 = Entry::create('cn=2,dc=foo,dc=bar', ['cn' => '2']);

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2)));

        $subject = new ServerPagingHandler(
            backend: $this->mockBackend,
            filterEvaluator: $this->mockFilterEvaluator,
            accessControl: $this->mockAccessControl,
            requestHistory: $this->requestHistory,
            schema: $this->schema,
            limits: new SearchLimits(maxSearchPageSize: 1),
        );
        $this->drive($subject, $message);

        // Only 1 entry returned despite client requesting page size 10.
        self::assertEquals(
            [new LdapMessageResponse(2, new SearchResultEntry($entry1))],
            $this->entryMessages(),
        );
        // Non-empty cookie means entry2 is still waiting.
        self::assertNotSame('', $this->donePagingControl()->getCookie());
    }

    public function test_server_max_page_size_is_used_when_client_sends_zero(): void
    {
        // pageSize=0 at the start means "server chooses".
        $message = $this->makeSearchMessage(size: 0);

        $entry1 = Entry::create('cn=1,dc=foo,dc=bar', ['cn' => '1']);
        $entry2 = Entry::create('cn=2,dc=foo,dc=bar', ['cn' => '2']);
        $entry3 = Entry::create('cn=3,dc=foo,dc=bar', ['cn' => '3']);

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2, $entry3)));

        $subject = new ServerPagingHandler(
            backend: $this->mockBackend,
            filterEvaluator: $this->mockFilterEvaluator,
            accessControl: $this->mockAccessControl,
            requestHistory: $this->requestHistory,
            schema: $this->schema,
            limits: new SearchLimits(maxSearchPageSize: 2),
        );
        $this->drive($subject, $message);

        // Server applies its max of 2 entries per page.
        self::assertCount(2, $this->entryMessages());
        // entry3 still waiting.
        self::assertNotSame('', $this->donePagingControl()->getCookie());
    }

    public function test_client_page_size_is_honoured_when_below_server_max(): void
    {
        $message = $this->makeSearchMessage(size: 1);

        $entry1 = Entry::create('cn=1,dc=foo,dc=bar', ['cn' => '1']);
        $entry2 = Entry::create('cn=2,dc=foo,dc=bar', ['cn' => '2']);

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2)));

        $subject = new ServerPagingHandler(
            backend: $this->mockBackend,
            filterEvaluator: $this->mockFilterEvaluator,
            accessControl: $this->mockAccessControl,
            requestHistory: $this->requestHistory,
            schema: $this->schema,
            limits: new SearchLimits(maxSearchPageSize: 5),
        );
        $this->drive($subject, $message);

        // Client requested 1 per page; server max is 5 — client's lower value wins.
        self::assertEquals(
            [new LdapMessageResponse(2, new SearchResultEntry($entry1))],
            $this->entryMessages(),
        );
        self::assertNotSame('', $this->donePagingControl()->getCookie());
    }

    public function test_it_should_suppress_entry_when_filter_entry_returns_null(): void
    {
        $entry1 = Entry::create(
            'cn=1,dc=foo,dc=bar',
            ['cn' => '1'],
        );
        $entry2 = Entry::create(
            'cn=2,dc=foo,dc=bar',
            ['cn' => '2'],
        );
        $message = $this->makeSearchMessage(size: 10);

        $mockAccessControl = $this->createMock(AccessControlInterface::class);
        $mockAccessControl
            ->method('filterEntry')
            ->willReturnCallback(static function (TokenInterface $token, Entry $entry) use ($entry1): ?Entry {
                return $entry === $entry1 ? null : $entry;
            });

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator(
                $entry1,
                $entry2,
            )));

        $subject = new ServerPagingHandler(
            backend: $this->mockBackend,
            filterEvaluator: $this->mockFilterEvaluator,
            accessControl: $mockAccessControl,
            requestHistory: $this->requestHistory,
            schema: $this->schema,
        );
        $this->drive($subject, $message);

        self::assertEquals(
            [new LdapMessageResponse(2, new SearchResultEntry($entry2))],
            $this->entryMessages(),
        );
    }

    public function test_it_should_skip_entry_when_filter_no_longer_matches_after_acl_stripping(): void
    {
        $entry = Entry::create(
            'cn=1,dc=foo,dc=bar',
            ['cn' => '1', 'secret' => 'val'],
        );
        $stripped = Entry::create(
            'cn=1,dc=foo,dc=bar',
            ['cn' => '1'],
        );
        $message = $this->makeSearchMessage(size: 10);

        $mockAccessControl = $this->createMock(AccessControlInterface::class);
        $mockAccessControl
            ->method('filterEntry')
            ->willReturn($stripped);

        $mockFilterEvaluator = $this->createMock(FilterEvaluatorInterface::class);
        $mockFilterEvaluator
            ->method('evaluate')
            ->willReturnCallback(static fn(Entry $e): bool => $e === $entry);

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry)));

        $subject = new ServerPagingHandler(
            backend: $this->mockBackend,
            filterEvaluator: $mockFilterEvaluator,
            accessControl: $mockAccessControl,
            requestHistory: $this->requestHistory,
            schema: $this->schema,
        );
        $this->drive($subject, $message);

        self::assertSame([], $this->entryMessages());
    }

    public function test_sort_control_appends_sorting_response_control_to_done_message(): void
    {
        $message = new LdapMessageRequest(
            2,
            $this->makeSearchRequest(),
            new PagingControl(10, ''),
            new SortingControl(SortKey::ascending('cn')),
        );

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator()));

        $this->drive(
            $this->subject,
            $message,
        );

        $sortControl = $this->doneMessage()->controls()->get(Control::OID_SORTING_RESPONSE);
        self::assertInstanceOf(
            SortingResponseControl::class,
            $sortControl,
        );
        self::assertSame(
            0,
            $sortControl->getResult(),
        );
    }

    public function test_sort_by_unknown_attribute_reports_no_such_attribute(): void
    {
        $message = new LdapMessageRequest(
            2,
            $this->makeSearchRequest(),
            new PagingControl(10, ''),
            new SortingControl(SortKey::ascending('bogusAttr')),
        );

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator()));

        $this->drive(
            $this->subject,
            $message,
        );

        $sortControl = $this->doneMessage()->controls()->get(Control::OID_SORTING_RESPONSE);
        self::assertInstanceOf(
            SortingResponseControl::class,
            $sortControl,
        );
        self::assertSame(
            ResultCode::NO_SUCH_ATTRIBUTE,
            $sortControl->getResult(),
        );
        self::assertSame(
            'bogusAttr',
            $sortControl->getAttribute(),
        );
    }

    public function test_an_unsortable_critical_sort_fails_the_paged_search_and_returns_no_entries(): void
    {
        $message = new LdapMessageRequest(
            2,
            $this->makeSearchRequest(),
            new PagingControl(10, ''),
            (new SortingControl(SortKey::ascending('bogusAttr')))->setCriticality(true),
        );

        $this->mockBackend
            ->expects(self::never())
            ->method('search');

        $this->drive(
            $this->subject,
            $message,
        );

        self::assertCount(
            1,
            $this->sentMessages,
            'No entries may be returned when a critical sort cannot be honored.',
        );

        $done = $this->doneMessage();
        $response = $done->getResponse();
        self::assertInstanceOf(
            SearchResultDone::class,
            $response,
        );
        self::assertSame(
            ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
            $response->getResultCode(),
        );
        self::assertInstanceOf(
            SortingResponseControl::class,
            $done->controls()->get(Control::OID_SORTING_RESPONSE),
        );
    }

    public function test_an_unsortable_critical_sort_discards_the_paged_result_set(): void
    {
        $message = new LdapMessageRequest(
            2,
            $this->makeSearchRequest(),
            new PagingControl(10, ''),
            (new SortingControl(SortKey::ascending('bogusAttr')))->setCriticality(true),
        );

        $this->drive(
            $this->subject,
            $message,
        );

        $paging = $this->doneMessage()->controls()->get(Control::OID_PAGING);
        self::assertInstanceOf(
            PagingControl::class,
            $paging,
        );
        self::assertSame(
            '',
            $paging->getCookie(),
        );
        self::assertSame(
            0,
            $this->requestHistory->pagingRequest()->count(),
        );
    }

    public function test_an_unsortable_non_critical_paged_sort_still_returns_entries(): void
    {
        $message = new LdapMessageRequest(
            2,
            $this->makeSearchRequest(),
            new PagingControl(10, ''),
            new SortingControl(SortKey::ascending('bogusAttr')),
        );

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator(
                Entry::create('dc=foo,dc=bar', ['cn' => 'foo']),
            )));

        $this->drive(
            $this->subject,
            $message,
        );

        $response = $this->doneMessage()->getResponse();
        self::assertInstanceOf(
            SearchResultDone::class,
            $response,
        );
        self::assertSame(
            ResultCode::SUCCESS,
            $response->getResultCode(),
        );
        self::assertGreaterThan(
            1,
            count($this->sentMessages),
        );
    }

    public function test_no_sort_control_does_not_append_sorting_response_control(): void
    {
        $message = $this->makeSearchMessage(size: 10);

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator()));

        $this->drive(
            $this->subject,
            $message,
        );

        self::assertNull(
            $this->doneMessage()->controls()->get(Control::OID_SORTING_RESPONSE),
        );
    }

    public function test_matched_dn_from_exception_is_used_in_SearchResultDone_when_access_control_allows(): void
    {
        $matchedDn = new Dn('dc=foo,dc=bar');
        $matchedEntry = Entry::create('dc=foo,dc=bar');

        $message = $this->makeSearchMessage(size: 10);

        $this->mockBackend
            ->method('search')
            ->willThrowException(new OperationException(
                'No such object.',
                ResultCode::NO_SUCH_OBJECT,
                null,
                $matchedDn,
            ));
        $this->mockBackend
            ->method('get')
            ->willReturn($matchedEntry);

        $this->drive(
            $this->subject,
            $message,
        );

        $done = $this->doneMessage()->getResponse();
        self::assertInstanceOf(SearchResultDone::class, $done);
        self::assertSame(
            ResultCode::NO_SUCH_OBJECT,
            $done->getResultCode(),
        );
        self::assertSame(
            'dc=foo,dc=bar',
            $done->getDn()->toString(),
        );
    }

    public function test_matched_dn_is_dropped_when_access_control_hides_ancestor_on_paged_search(): void
    {
        $matchedDn = new Dn('dc=foo,dc=bar');
        $matchedEntry = Entry::create('dc=foo,dc=bar');

        $message = $this->makeSearchMessage(size: 10);

        $this->mockBackend
            ->method('search')
            ->willThrowException(new OperationException(
                'No such object.',
                ResultCode::NO_SUCH_OBJECT,
                null,
                $matchedDn,
            ));
        $this->mockBackend
            ->method('get')
            ->willReturn($matchedEntry);

        $mockAccessControl = $this->createMock(AccessControlInterface::class);
        $mockAccessControl
            ->method('filterEntry')
            ->willReturn(null);

        $subject = new ServerPagingHandler(
            backend: $this->mockBackend,
            filterEvaluator: $this->mockFilterEvaluator,
            accessControl: $mockAccessControl,
            requestHistory: $this->requestHistory,
            schema: $this->schema,
        );

        $this->drive(
            $subject,
            $message,
        );

        $done = $this->doneMessage()->getResponse();
        self::assertInstanceOf(SearchResultDone::class, $done);
        self::assertSame(
            ResultCode::NO_SUCH_OBJECT,
            $done->getResultCode(),
        );
        self::assertSame(
            '',
            $done->getDn()->toString(),
        );
    }

    private function drive(
        ServerPagingHandler $subject,
        LdapMessageRequest $message,
    ): OperationResult {
        $stream = $subject->handleRequest(
            $message,
            $this->mockToken,
        );

        return (new ResponseWriter($this->mockQueue))->write(
            $stream,
            $message->getMessageId(),
        );
    }

    private function makeGenerator(Entry ...$entries): Generator
    {
        yield from $entries;
    }

    /**
     * @return list<LdapMessageResponse>
     */
    private function entryMessages(): array
    {
        return array_values(array_filter(
            $this->sentMessages,
            static fn(LdapMessageResponse $m): bool => $m->getResponse() instanceof SearchResultEntry,
        ));
    }

    private function doneMessage(): LdapMessageResponse
    {
        foreach ($this->sentMessages as $message) {
            if ($message->getResponse() instanceof SearchResultDone) {
                return $message;
            }
        }

        self::fail('No SearchResultDone message was sent.');
    }

    private function donePagingControl(): PagingControl
    {
        $paging = $this->doneMessage()->controls()->get(Control::OID_PAGING);
        self::assertInstanceOf(PagingControl::class, $paging);

        return $paging;
    }

    private function makeExistingPagingRequest(
        int $size = 10,
        string $cookie = 'bar',
        string $nextCookie = 'foo',
        ?SearchRequest $searchRequest = null,
    ): PagingRequest {
        $searchReq = $searchRequest ?? $this->makeSearchRequest();

        $pagingReq = new PagingRequest(
            new PagingControl($size, $cookie),
            $searchReq,
            new ControlBag(),
            $nextCookie,
        );

        $pagingReq->markProcessed();
        $this->requestHistory->pagingRequest()->add($pagingReq);
        $this->requestHistory->storePagingGenerator($nextCookie, $this->makeGenerator());

        return $pagingReq;
    }

    private function makeSearchMessage(
        int $size = 10,
        string $cookie = '',
        ?SearchRequest $searchRequest = null,
    ): LdapMessageRequest {
        return new LdapMessageRequest(
            2,
            $searchRequest ?? $this->makeSearchRequest(),
            new PagingControl($size, $cookie),
        );
    }

    private function makeSearchRequest(string $filter = '(foo=bar)'): SearchRequest
    {
        return (new SearchRequest(Filters::raw($filter)))
            ->base('dc=foo,dc=bar');
    }
}
