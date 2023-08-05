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

use Closure;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Request\SyncRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientProtocolContext;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientSyncHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ResponseHandlerInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Result\SyncReferralResult;
use FreeDSx\Ldap\Sync\Session;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use spec\FreeDSx\Ldap\Sync\MockSyncEntryHandler;
use spec\FreeDSx\Ldap\Sync\MockSyncIdSetHandler;
use spec\FreeDSx\Ldap\Sync\MockSyncReferralHandler;
use spec\FreeDSx\Ldap\TestFactoryTrait;

class ClientSyncHandlerSpec extends ObjectBehavior
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
        $this->shouldHaveType(ClientSyncHandler::class);
    }


    public function it_should_implement_ResponseHandlerInterface(): void
    {
        $this->shouldBeAnInstanceOf(ResponseHandlerInterface::class);
    }

    public function it_should_implement_RequestHandlerInterface(): void
    {
        $this->shouldBeAnInstanceOf(RequestHandlerInterface::class);
    }

    public function it_should_set_a_default_DN_for_a_request_that_has_none(
        ClientProtocolContext $context,
        LdapMessageResponse $response,
        ClientQueue $queue,
        LdapMessageRequest $message,
        SyncRequest $request
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


    public function it_should_retrieve_results_until_it_receives_a_search_done_with_a_sync_done_control(
        ClientQueue $queue,
    ): void {
        $messageTo = new LdapMessageRequest(
            1,
            new SyncRequest(),
            new SyncRequestControl(),
        );
        $response = new LdapMessageResponse(
            1,
            new SearchResultEntry(new Entry('bar'))
        );

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
            new LdapMessageResponse(
                1,
                new SearchResultDone(
                    0,
                    'cn=foo',
                    'bar'
                ),
                new SyncDoneControl('foo')
            )
        );

        $queue->getMessage(1)
            ->shouldBeCalledTimes(5);

        $this->handleResponse(
            $messageTo,
            $response,
        )->shouldBeLike(
            $this::makeSearchResponseFromEntries(
                dn: 'cn=foo',
                diagnostic: 'bar',
                controls: [
                    new SyncDoneControl('foo'),
                ]
            )
        );
    }

    public function it_should_throw_an_exception_if_a_sync_request_control_was_not_provided(ClientQueue $queue, ): void
    {
        $this->shouldThrow(new RuntimeException(sprintf(
            'Expected a "%s", but there is none.',
            SyncRequestControl::class,
        )))->during(
            'handleResponse',
            [
                new LdapMessageRequest(
                    1,
                    new SyncRequest(),
                ),
                new LdapMessageResponse(
                    1,
                    new SearchResultEntry(new Entry('bar'))
                ),
                $queue,
                new ClientOptions(),
            ]
        );
    }

    public function it_should_process_a_sync_entry(
        ClientQueue $queue,
        MockSyncEntryHandler $syncEntryHandler,
    ): void {
        $entry = new Entry('bar');
        $syncState = new SyncStateControl(
            SyncStateControl::STATE_ADD,
            'foo',
            'bar'
        );

        $messageTo = new LdapMessageRequest(
            1,
            (new SyncRequest())
                ->useEntryHandler(Closure::fromCallable($syncEntryHandler->getWrappedObject())),
            new SyncRequestControl(),
        );
        $response = new LdapMessageResponse(
            1,
            new SearchResultEntry($entry),
            $syncState,
        );

        $queue->getMessage(1)->willReturn(
            new LdapMessageResponse(
                1,
                new SearchResultDone(
                    0,
                    'cn=foo',
                    'bar'
                ),
                new SyncDoneControl('foo')
            )
        );

        $syncEntryHandler->__invoke(
            Argument::that(function (SyncEntryResult $result) use ($response) {
                return $result->getMessage() === $response;
            }),
            Argument::type(Session::class),
        )->shouldBeCalledOnce();

        $this->handleResponse(
            $messageTo,
            $response,
        )->shouldBeLike(
            $this::makeSearchResponseFromEntries(
                dn: 'cn=foo',
                diagnostic: 'bar',
                controls: [
                    new SyncDoneControl('foo'),
                ]
            )
        );
    }

    public function it_should_process_a_sync_id_set(
        ClientQueue $queue,
        MockSyncIdSetHandler $mockSyncReferralHandler,
    ): void {
        $messageTo = new LdapMessageRequest(
            1,
            (new SyncRequest())
                ->useIdSetHandler(Closure::fromCallable($mockSyncReferralHandler->getWrappedObject())),
            new SyncRequestControl(),
        );
        $response = new LdapMessageResponse(
            1,
            new SyncIdSet(['bar']),
        );

        $queue->getMessage(1)->willReturn(
            new LdapMessageResponse(
                1,
                new SearchResultDone(
                    0,
                    'cn=foo',
                    'bar'
                ),
                new SyncDoneControl('foo')
            )
        );

        $mockSyncReferralHandler->__invoke(
            Argument::that(function (SyncIdSetResult $result) use ($response) {
                return $result->getMessage() === $response;
            }),
            Argument::type(Session::class),
        )->shouldBeCalledOnce();

        $this->handleResponse(
            $messageTo,
            $response,
        )->shouldBeLike(
            $this::makeSearchResponseFromEntries(
                dn: 'cn=foo',
                diagnostic: 'bar',
                controls: [
                    new SyncDoneControl('foo'),
                ]
            )
        );
    }

    public function it_should_process_a_sync_referral(
        ClientQueue $queue,
        MockSyncReferralHandler $mockSyncReferralHandler,
    ): void {
        $referral = new LdapUrl('bar');
        $syncState = new SyncStateControl(
            SyncStateControl::STATE_ADD,
            'foo',
            'bar'
        );

        $messageTo = new LdapMessageRequest(
            1,
            (new SyncRequest())
                ->useReferralHandler(Closure::fromCallable($mockSyncReferralHandler->getWrappedObject())),
            new SyncRequestControl(),
        );
        $response = new LdapMessageResponse(
            1,
            new SearchResultReference($referral),
            $syncState,
        );

        $queue->getMessage(1)->willReturn(
            new LdapMessageResponse(
                1,
                new SearchResultDone(
                    0,
                    'cn=foo',
                    'bar'
                ),
                new SyncDoneControl('foo')
            )
        );

        $mockSyncReferralHandler->__invoke(
            Argument::that(function (SyncReferralResult $result) use ($response) {
                return $result->getMessage() === $response;
            }),
            Argument::type(Session::class),
        )->shouldBeCalledOnce();

        $this->handleResponse(
            $messageTo,
            $response,
        )->shouldBeLike(
            $this::makeSearchResponseFromEntries(
                dn: 'cn=foo',
                diagnostic: 'bar',
                controls: [
                    new SyncDoneControl('foo'),
                ]
            )
        );
    }
}
