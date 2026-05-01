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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPagingHandler;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\RequestHistory;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
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

    private ServerPagingHandler $subject;

    private TokenInterface&MockObject $mockToken;

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
        $this->requestHistory = new RequestHistory();
        $this->sentMessages = [];

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $this->mockQueue
            ->method('sendMessages')
            ->willReturnCallback(function (iterable $messages): ServerQueue {
                foreach ($messages as $message) {
                    $this->sentMessages[] = $message;
                }

                return $this->mockQueue;
            });

        $this->subject = new ServerPagingHandler(
            queue: $this->mockQueue,
            backend: $this->mockBackend,
            filterEvaluator: $this->mockFilterEvaluator,
            requestHistory: $this->requestHistory,
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
            static fn (LdapMessageResponse $m): bool => $m->getResponse() instanceof SearchResultEntry,
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

        $this->subject->handleRequest(
            $message,
            $this->mockToken,
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

        $this->subject->handleRequest(
            $message,
            $this->mockToken,
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

        $this->subject->handleRequest($firstMessage, $this->mockToken);

        $capturedCookie = $this->donePagingControl()->getCookie();
        self::assertNotSame('', $capturedCookie);

        // Second page: use the captured cookie.
        $pagingReq = $this->requestHistory->pagingRequest()->findByNextCookie($capturedCookie);
        $secondMessage = $this->makeSearchMessage(
            size: 10,
            cookie: $capturedCookie,
            searchRequest: $pagingReq->getSearchRequest(),
        );

        $this->subject->handleRequest($secondMessage, $this->mockToken);
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

        $this->subject->handleRequest(
            $message,
            $this->mockToken,
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

        $this->subject->handleRequest(
            $message,
            $this->mockToken,
        );

        self::assertEquals(
            [
                new LdapMessageResponse(
                    $message->getMessageId(),
                    new SearchResultDone(
                        ResultCode::OPERATIONS_ERROR,
                        'dc=foo,dc=bar',
                        "The search request and controls must be identical between paging requests."
                    ),
                    new PagingControl(0, '')
                ),
            ],
            $this->sentMessages,
        );
    }

    public function test_it_sends_an_operations_error_when_the_paging_generator_has_expired(): void
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

        $this->subject->handleRequest(
            $message,
            $this->mockToken
        );

        self::assertSame([], $this->entryMessages());
        $done = $this->doneMessage()->getResponse();
        self::assertInstanceOf(SearchResultDone::class, $done);
        self::assertSame(ResultCode::OPERATIONS_ERROR, $done->getResultCode());
        self::assertSame('', $this->donePagingControl()->getCookie());
    }

    public function test_it_throws_an_exception_if_the_paging_cookie_does_not_exist(): void
    {
        $message = $this->makeSearchMessage(
            size: 10,
            cookie: 'nonexistent-cookie',
            searchRequest: $this->makeSearchRequest('(oh=no)'),
        );

        self::expectExceptionObject(new OperationException("The supplied cookie is invalid."));

        $this->subject->handleRequest(
            $message,
            $this->mockToken,
        );
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

        $this->subject->handleRequest($message, $this->mockToken);

        self::assertEquals(
            [new LdapMessageResponse(2, new SearchResultEntry($entry1))],
            $this->entryMessages(),
        );

        $done = $this->doneMessage()->getResponse();
        self::assertInstanceOf(SearchResultDone::class, $done);
        self::assertSame(ResultCode::SIZE_LIMIT_EXCEEDED, $done->getResultCode());
        self::assertSame('', $this->donePagingControl()->getCookie());
    }

    public function test_it_should_accumulate_size_limit_across_pages(): void
    {
        $searchRequest = (new SearchRequest(Filters::raw('(foo=bar)')))
            ->base('dc=foo,dc=bar')
            ->sizeLimit(2);

        $entry1 = Entry::create('cn=1,dc=foo,dc=bar', ['cn' => '1']);
        $entry2 = Entry::create('cn=2,dc=foo,dc=bar', ['cn' => '2']);
        $entry3 = Entry::create('cn=3,dc=foo,dc=bar', ['cn' => '3']);

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2, $entry3)));

        // First page: pageSize=1, sizeLimit=2 — gets entry1, stores generator
        $this->subject->handleRequest(
            $this->makeSearchMessage(size: 1, searchRequest: $searchRequest),
            $this->mockToken,
        );

        $capturedCookie = $this->donePagingControl()->getCookie();
        self::assertNotSame('', $capturedCookie, 'Expected a non-empty cookie after the first page.');

        // Second page: totalSent=1, gets entry2 — hits sizeLimit(2), returns SIZE_LIMIT_EXCEEDED
        $pagingReq = $this->requestHistory->pagingRequest()->findByNextCookie($capturedCookie);
        $this->subject->handleRequest(
            $this->makeSearchMessage(size: 10, cookie: $capturedCookie, searchRequest: $pagingReq->getSearchRequest()),
            $this->mockToken,
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

    private function makeExistingPagingRequest(
        int $size = 10,
        string $cookie = 'bar',
        string $nextCookie = 'foo',
        ?SearchRequest $searchRequest = null
    ): PagingRequest {
        $searchReq = $searchRequest ?? $this->makeSearchRequest();

        $pagingReq = new PagingRequest(
            new PagingControl($size, $cookie),
            $searchReq,
            new ControlBag(),
            $nextCookie
        );

        $pagingReq->markProcessed();
        $this->requestHistory->pagingRequest()->add($pagingReq);
        $this->requestHistory->storePagingGenerator($nextCookie, $this->makeGenerator());

        return $pagingReq;
    }

    private function makeSearchMessage(
        int $size = 10,
        string $cookie = '',
        ?SearchRequest $searchRequest = null
    ): LdapMessageRequest {
        return new LdapMessageRequest(
            2,
            $searchRequest ?? $this->makeSearchRequest(),
            new PagingControl($size, $cookie)
        );
    }

    private function makeSearchRequest(string $filter = '(foo=bar)'): SearchRequest
    {
        return (new SearchRequest(Filters::raw($filter)))
            ->base('dc=foo,dc=bar');
    }
}
