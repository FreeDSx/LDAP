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
use FreeDSx\Ldap\Entry\Entries;
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
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\Paging\PagingResponse;
use FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface;
use FreeDSx\Ldap\Server\RequestHistory;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class ServerPagingHandlerTest extends TestCase
{
    private RequestHistory $requestHistory;

    private ServerQueue&MockObject $mockQueue;

    private PagingHandlerInterface&MockObject $mockPagingHandler;

    private ServerPagingHandler $subject;

    private TokenInterface&MockObject $mockToken;

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockPagingHandler = $this->createMock(PagingHandlerInterface::class);
        $this->requestHistory = new RequestHistory();

        $this->subject = new ServerPagingHandler(
            $this->mockQueue,
            $this->mockPagingHandler,
            $this->requestHistory,
        );
    }

    public function test_it_should_send_a_request_to_the_paging_handler_on_paging_start(): void
    {
        $message = $this->makeSearchMessage();

        $entries = new Entries(
            Entry::create('dc=foo,dc=bar', ['cn' => 'foo']),
            Entry::create('dc=bar,dc=foo', ['cn' => 'bar'])
        );

        $resultEntry1 = new LdapMessageResponse(
            2,
            new SearchResultEntry(Entry::create('dc=foo,dc=bar', ['cn' => 'foo']))
        );
        $resultEntry2 = new LdapMessageResponse(
            2,
            new SearchResultEntry(Entry::create('dc=bar,dc=foo', ['cn' => 'bar']))
        );

        $response = PagingResponse::make($entries);

        $this->mockPagingHandler
            ->expects($this->once())
            ->method('page')
            ->willReturn($response);

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                $resultEntry1,
                $resultEntry2,
                self::callback(function (LdapMessageResponse $response) {
                    /** @var PagingControl $paging */
                    $paging = $response->controls()->get(Control::OID_PAGING);

                    return $paging && $paging->getCookie() !== '';
                })
            );

        $this->subject->handleRequest(
            $message,
            $this->mockToken,
        );
    }

    public function test_it_should_send_the_correct_response_if_paging_is_complete(): void
    {
        $message = $this->makeSearchMessage();

        $entries = new Entries(
            Entry::create('dc=foo,dc=bar', ['cn' => 'foo']),
            Entry::create('dc=bar,dc=foo', ['cn' => 'bar'])
        );

        $resultEntry1 = new LdapMessageResponse(
            2,
            new SearchResultEntry(Entry::create('dc=foo,dc=bar', ['cn' => 'foo']))
        );
        $resultEntry2 = new LdapMessageResponse(
            2,
            new SearchResultEntry(Entry::create('dc=bar,dc=foo', ['cn' => 'bar']))
        );

        $response = PagingResponse::makeFinal($entries);

        $this->mockPagingHandler
            ->expects($this->once())
            ->method('page')
            ->willReturn($response);

        $this->mockPagingHandler
            ->expects($this->once())
            ->method('remove');

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                $resultEntry1,
                $resultEntry2,
                self::callback(function (LdapMessageResponse $response) {
                    /** @var PagingControl $paging */
                    $paging = $response->controls()->get(Control::OID_PAGING);

                    return $paging && $paging->getCookie() === '';
                })
            );

        $this->subject->handleRequest(
            $message,
            $this->mockToken,
        );
    }

    public function test_it_should_send_the_correct_response_if_paging_is_abandoned(): void
    {
        $pagingReq = $this->makeExistingPagingRequest();
        $message = $this->makeSearchMessage(
            0,
            'foo',
            $pagingReq->getSearchRequest()
        );

        $this->mockPagingHandler
            ->expects($this->never())
            ->method('page');

        $this->mockPagingHandler
            ->expects($this->once())
            ->method('remove');

        $this->mockQueue
            ->expects($this->once())
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
        $this->makeExistingPagingRequest();
        $message = $this->makeSearchMessage(
            0,
            'foo',
            $this->makeSearchRequest('(oh=no)')
        );

        $this->mockPagingHandler
            ->expects($this->never())
            ->method('page');
        $this->mockPagingHandler
            ->expects($this->once())
            ->method('remove');

        $this->mockQueue
            ->expects($this->once())
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
            0,
            'foo',
            $this->makeSearchRequest('(oh=no)')
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
