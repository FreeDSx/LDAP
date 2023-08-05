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

namespace spec\FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientProtocolContext;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientSearchHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ResponseHandlerInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use spec\FreeDSx\Ldap\TestFactoryTrait;

class ClientSearchHandlerSpec extends ObjectBehavior
{
    use TestFactoryTrait;

    public function let(ClientQueue $queue): void
    {
        $this->beConstructedWith(
            $queue,
            new ClientOptions(),
        );
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ClientSearchHandler::class);
    }

    public function it_should_implement_ResponseHandlerInterface(): void
    {
        $this->shouldBeAnInstanceOf(ResponseHandlerInterface::class);
    }

    public function it_should_implement_RequestHandlerInterface(): void
    {
        $this->shouldBeAnInstanceOf(RequestHandlerInterface::class);
    }

    public function it_should_send_a_request_and_get_a_response(
        ClientProtocolContext $context,
        ClientQueue $queue,
        LdapMessageResponse $response
    ): void {
        $request = Operations::search(new EqualityFilter('foo', 'bar'));
        $message = new LdapMessageRequest(1, $request);

        $queue->sendMessage($message)->shouldBeCalledOnce();
        $queue->getMessage(1)->shouldBeCalledOnce()->willReturn($response);

        $context->getRequest()->willReturn($request);
        $context->messageToSend()->willReturn($message);

        $this->handleRequest($context)->shouldBeEqualTo($response);
    }

    public function it_should_set_a_default_DN_for_a_request_that_has_none(
        ClientProtocolContext $context,
        LdapMessageResponse $response,
        ClientQueue $queue,
        LdapMessageRequest $message,
        SearchRequest $request
    ): void {
        $this->beConstructedWith(
            $queue,
            (new ClientOptions())
                ->setBaseDn('cn=foo')
        );
        $queue->getMessage(1)->shouldBeCalled()->willReturn($response);
        $queue->sendMessage($message)->shouldBeCalledOnce();

        $message->getMessageId()->willReturn(1);
        $message->getRequest()->willReturn($request);
        $request->getBaseDn()->willReturn(null);

        $context->messageToSend()->willReturn($message);
        $context->getRequest()->willReturn($request);

        $request->setBaseDn('cn=foo')
            ->shouldBeCalledOnce();

        $this->handleRequest($context);
    }

    public function it_should_not_keep_getting_messages_when_the_first_result_is_search_done(ClientQueue $queue): void
    {
        $messageTo = new LdapMessageRequest(1, new SearchRequest(new EqualityFilter('foo', 'bar')));
        $response = new LdapMessageResponse(1, new SearchResultDone(0));

        $queue->getMessage(Argument::any())
            ->shouldNotBeCalled();

        $this->handleResponse(
            $messageTo,
            $response,
        )->getResponse()
            ->shouldBeAnInstanceOf(SearchResponse::class);
    }

    public function it_should_retrieve_results_until_it_receives_a_search_done_and_return_all_results(ClientQueue $queue): void
    {
        $messageTo = new LdapMessageRequest(1, new SearchRequest(new EqualityFilter('foo', 'bar')));
        $response = new LdapMessageResponse(1, new SearchResultEntry(new Entry('bar')));

        $entries = [
            new SearchResultEntry(new Entry('foo')),
            new SearchResultEntry(new Entry('foo')),
            new SearchResultEntry(new Entry('foo')),
        ];
        $referrals = [
            new SearchResultReference(new LdapUrl('ldap://foo')),
        ];

        $queue->getMessage(1)->willReturn(
            new LdapMessageResponse(1, $entries[0]),
            new LdapMessageResponse(1, $entries[1]),
            new LdapMessageResponse(1, $referrals[0]),
            new LdapMessageResponse(1, $entries[2]),
            new LdapMessageResponse(1, new SearchResultDone(
                0,
                'cn=foo',
                'bar'
            ))
        );

        $queue->getMessage(1)->shouldBeCalledTimes(5);
        $this->handleResponse(
            $messageTo,
            $response,
        )->shouldBeLike(
            $this::makeSearchResponseFromEntries(
                dn: 'cn=foo',
                diagnostic: 'bar',
                searchEntryResults: [
                    new SearchResultEntry(new Entry('bar')),
                    ...$entries,
                ],
                searchReferralResults: $referrals,
            )
        );
    }

    public function it_should_throw_an_exception_if_the_result_code_is_not_success(ClientQueue $queue): void
    {
        $messageTo = new LdapMessageRequest(1, new SearchRequest(new EqualityFilter('foo', 'bar')));
        $response = new LdapMessageResponse(1, new SearchResultDone(ResultCode::SIZE_LIMIT_EXCEEDED));

        $this->shouldThrow(OperationException::class)->during(
            'handleResponse',
            [
                $messageTo,
                $response,
                $queue,
                new ClientOptions()
            ]
        );
    }
}
