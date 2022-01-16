<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPagingHandler;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\Paging\PagingResponse;
use FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\RequestHistory;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ServerPagingHandlerSpec extends ObjectBehavior
{
    /**
     * @var RequestHistory
     */
    private $requestHistory;

    public function let(PagingHandlerInterface $pagingHandler)
    {
        $this->requestHistory = new RequestHistory();

        $this->beConstructedWith(
            $pagingHandler,
            $this->requestHistory
        );
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(ServerPagingHandler::class);
    }

    public function it_should_send_a_request_to_the_paging_handler_on_paging_start(
        ServerQueue $queue,
        RequestHandlerInterface $handler,
        TokenInterface $token,
        PagingHandlerInterface $pagingHandler
    ) {
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

        $pagingHandler->page(Argument::any(), Argument::any())
            ->shouldBeCalled()
            ->willReturn($response);

        $queue->sendMessage(
            $resultEntry1,
            $resultEntry2,
            Argument::that(function (LdapMessageResponse $response) {
                /** @var PagingControl $paging */
                $paging = $response->controls()->get(Control::OID_PAGING);

                return $paging && $paging->getCookie() !== '';
            })
        )->shouldBeCalled();

        $this->handleRequest(
            $message,
            $token,
            $handler,
            $queue,
            []
        );
    }

    public function it_should_send_the_correct_response_if_paging_is_complete(
        ServerQueue $queue,
        RequestHandlerInterface $handler,
        TokenInterface $token,
        PagingHandlerInterface $pagingHandler
    ) {
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

        $pagingHandler->page(Argument::any(), Argument::any())
            ->shouldBeCalled()
            ->willReturn($response);

        $pagingHandler->remove(Argument::any(), Argument::any())
            ->shouldBeCalled();

        $queue->sendMessage(
            $resultEntry1,
            $resultEntry2,
            Argument::that(function (LdapMessageResponse $response) {
                /** @var PagingControl $paging */
                $paging = $response->controls()->get(Control::OID_PAGING);

                return $paging && $paging->getCookie() === '';
            })
        )->shouldBeCalled();

        $this->handleRequest(
            $message,
            $token,
            $handler,
            $queue,
            []
        );
    }

    public function it_should_send_the_correct_response_if_paging_is_abandoned(
        ServerQueue $queue,
        RequestHandlerInterface $handler,
        TokenInterface $token,
        PagingHandlerInterface $pagingHandler
    ) {
        $pagingReq = $this->makeExistingPagingRequest();
        $message = $this->makeSearchMessage(
            0,
            'foo',
            $pagingReq->getSearchRequest()
        );

        $pagingHandler->page(Argument::any(), Argument::any())
            ->shouldNotBeCalled();

        $pagingHandler->remove(Argument::any(), Argument::any())
            ->shouldBeCalled();

        $queue->sendMessage(
            Argument::that(function (LdapMessageResponse $response) {
                /** @var PagingControl $paging */
                $paging = $response->controls()->get(Control::OID_PAGING);

                return $paging && $paging->getCookie() === '';
            })
        )->shouldBeCalled();

        $this->handleRequest(
            $message,
            $token,
            $handler,
            $queue,
            []
        );
    }

    public function it_throws_an_exception_if_the_old_and_new_paging_requests_are_different(
        ServerQueue $queue,
        RequestHandlerInterface $handler,
        TokenInterface $token,
        PagingHandlerInterface $pagingHandler
    ) {
        $this->makeExistingPagingRequest();
        $message = $this->makeSearchMessage(
            0,
            'foo',
            $this->makeSearchRequest('(oh=no)')
        );

        $pagingHandler->page(Argument::any(), Argument::any())
            ->shouldNotBeCalled();
        $pagingHandler->remove(Argument::any(), Argument::any())
            ->shouldNotBeCalled();

        $this->shouldThrow(new OperationException("The search request and controls must be identical between paging requests."))->during('handleRequest', [
            $message,
            $token,
            $handler,
            $queue,
            []
        ]);
    }

    public function it_throws_an_exception_if_the_paging_cookie_does_not_exist(
        ServerQueue $queue,
        RequestHandlerInterface $handler,
        TokenInterface $token
    ) {
        $message = $this->makeSearchMessage(
            0,
            'foo',
            $this->makeSearchRequest('(oh=no)')
        );

        $this->shouldThrow(new OperationException("The supplied cookie is invalid."))->during('handleRequest', [
            $message,
            $token,
            $handler,
            $queue,
            []
        ]);
    }

    private function makeExistingPagingRequest(
        int $size = 10,
        string $cookie = 'bar',
        string $nextCookie = 'foo',
        SearchRequest $searchRequest = null
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
        SearchRequest $searchRequest = null
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
