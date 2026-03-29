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
use FreeDSx\Ldap\Server\Backend\SearchContext;
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

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockBackend = $this->createMock(LdapBackendInterface::class);
        $this->mockFilterEvaluator = $this->createMock(FilterEvaluatorInterface::class);
        $this->requestHistory = new RequestHistory();

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

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

    public function test_it_should_call_the_backend_search_on_paging_start_and_return_entries(): void
    {
        $message = $this->makeSearchMessage(size: 10);

        $entry1 = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);
        $entry2 = Entry::create('dc=bar,dc=foo', ['cn' => 'bar']);

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->with(self::isInstanceOf(SearchContext::class))
            ->willReturn($this->makeGenerator($entry1, $entry2));

        $resultEntry1 = new LdapMessageResponse(
            2,
            new SearchResultEntry($entry1)
        );
        $resultEntry2 = new LdapMessageResponse(
            2,
            new SearchResultEntry($entry2)
        );

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(
                $resultEntry1,
                $resultEntry2,
                self::callback(function (LdapMessageResponse $response) {
                    /** @var PagingControl $paging */
                    $paging = $response->controls()->get(Control::OID_PAGING);

                    // Generator was exhausted with only 2 entries, so paging is complete (cookie='')
                    return $paging && $paging->getCookie() === '';
                })
            );

        $this->subject->handleRequest(
            $message,
            $this->mockToken,
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
            ->willReturn($this->makeGenerator($entry1, $entry2));

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(
                new LdapMessageResponse(2, new SearchResultEntry($entry1)),
                self::callback(function (LdapMessageResponse $response) {
                    /** @var PagingControl $paging */
                    $paging = $response->controls()->get(Control::OID_PAGING);

                    // Non-empty cookie means more entries remain.
                    return $paging && $paging->getCookie() !== '';
                })
            );

        $this->subject->handleRequest(
            $message,
            $this->mockToken,
        );
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
            ->willReturn($this->makeGenerator($entry1, $entry2));

        $capturedCookie = '';

        $this->mockQueue
            ->method('sendMessage')
            ->willReturnCallback(function (LdapMessageResponse ...$responses) use (&$capturedCookie) {
                foreach ($responses as $response) {
                    $paging = $response->controls()->get(Control::OID_PAGING);
                    if ($paging instanceof PagingControl && $paging->getCookie() !== '') {
                        $capturedCookie = $paging->getCookie();
                    }
                }

                return $this->mockQueue;
            });

        $this->subject->handleRequest($firstMessage, $this->mockToken);

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

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(function (LdapMessageResponse $response) {
                /** @var PagingControl $paging */
                $paging = $response->controls()->get(Control::OID_PAGING);

                return $paging && $paging->getCookie() === '';
            }));

        $this->subject->handleRequest(
            $message,
            $this->mockToken,
        );
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

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::equalTo(
                new LdapMessageResponse(
                    $message->getMessageId(),
                    new SearchResultDone(
                        ResultCode::OPERATIONS_ERROR,
                        'dc=foo,dc=bar',
                        "The search request and controls must be identical between paging requests."
                    ),
                    ...[new PagingControl(
                        0,
                        ''
                    )]
                )
            ));

        $this->subject->handleRequest(
            $message,
            $this->mockToken,
        );
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
