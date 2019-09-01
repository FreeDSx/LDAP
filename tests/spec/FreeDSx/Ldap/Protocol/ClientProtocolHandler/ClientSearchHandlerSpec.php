<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientSearchHandler;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\LdapQueue;
use FreeDSx\Ldap\Protocol\RequestHandlerInterface;
use FreeDSx\Ldap\Protocol\ResponseHandlerInterface;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ClientSearchHandlerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ClientSearchHandler::class);
    }

    function it_should_implement_ResponseHandlerInterface()
    {
        $this->shouldBeAnInstanceOf(ResponseHandlerInterface::class);
    }

    function it_should_implement_RequestHandlerInterface()
    {
        $this->shouldBeAnInstanceOf(RequestHandlerInterface::class);
    }

    function it_should_send_a_request_and_get_a_response(LdapQueue $queue, LdapMessageResponse $response)
    {
        $message = new LdapMessageRequest(1, Operations::search(new EqualityFilter('foo', 'bar')));

        $queue->sendMessage($message)->shouldBeCalledOnce();
        $queue->getMessage(1)->shouldBeCalledOnce()->willReturn($response);

        $this->handleRequest($message, $queue, [])->shouldBeEqualTo($response);
    }

    function it_should_set_a_default_DN_for_a_request_that_has_none(LdapMessageResponse $response, LdapQueue $queue, LdapMessageRequest $message, SearchRequest $request)
    {
        $queue->getMessage(1)->shouldBeCalled()->willReturn($response);
        $queue->sendMessage($message)->shouldBeCalledOnce();

        $message->getMessageId()->willReturn(1);
        $message->getRequest()->willReturn($request);
        $request->getBaseDn()->willReturn(null);

        $request->setBaseDn('cn=foo')->shouldBeCalledOnce();
        $this->handleRequest($message, $queue, ['base_dn' => 'cn=foo']);
    }

    function it_should_not_keep_getting_messages_when_the_first_result_is_search_done(LdapQueue $queue)
    {
        $messageTo = new LdapMessageRequest(1, new SearchRequest(new EqualityFilter('foo', 'bar')));
        $response = new LdapMessageResponse(1, new SearchResultDone(0));

        $queue->getMessage(Argument::any())->shouldNotBeCalled();
        $this->handleResponse($messageTo, $response, $queue, [])->getResponse()->shouldBeAnInstanceOf(SearchResponse::class);
    }

    function it_should_retrieve_results_until_it_receives_a_search_done_and_return_all_results(LdapQueue $queue)
    {
        $messageTo = new LdapMessageRequest(1, new SearchRequest(new EqualityFilter('foo', 'bar')));
        $response = new LdapMessageResponse(1, new SearchResultEntry(new Entry('bar')));

        $queue->getMessage(1)->willReturn(
            new LdapMessageResponse(1, new SearchResultEntry(new Entry('foo'))),
            new LdapMessageResponse(1, new SearchResultEntry(new Entry('foo'))),
            new LdapMessageResponse(1, new SearchResultReference()),
            new LdapMessageResponse(1, new SearchResultEntry(new Entry('foo'))),
            new LdapMessageResponse(1, new SearchResultDone(0, 'cn=foo', 'bar'))
         );

        $queue->getMessage(1)->shouldBeCalledTimes(5);
        $this->handleResponse($messageTo, $response, $queue, [])->shouldBeLike(
            new LdapMessageResponse(1, new SearchResponse(new LdapResult(0, 'cn=foo', 'bar'), new Entries(
                new Entry('bar'),
                new Entry('foo'),
                new Entry('foo'),
                new Entry('foo')
            ))));
    }

    function it_should_throw_an_exception_if_the_result_code_is_not_success(LdapQueue $queue)
    {
        $messageTo = new LdapMessageRequest(1, new SearchRequest(new EqualityFilter('foo', 'bar')));
        $response = new LdapMessageResponse(1, new SearchResultDone(ResultCode::SIZE_LIMIT_EXCEEDED));

        $this->shouldThrow(OperationException::class)->during('handleResponse', [$messageTo, $response, $queue, []]);
    }
}
