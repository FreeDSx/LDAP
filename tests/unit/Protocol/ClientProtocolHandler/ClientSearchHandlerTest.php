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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ClientProtocolHandler;

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
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientSearchHandler;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Unit\FreeDSx\Ldap\TestFactoryTrait;

final class ClientSearchHandlerTest extends TestCase
{
    use TestFactoryTrait;

    private ClientSearchHandler $subject;

    private ClientQueue&MockObject $mockQueue;

    private ClientOptions $options;

    private LdapMessageResponse&MockObject $mockResponse;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ClientQueue::class);
        $this->mockResponse = $this->createMock(LdapMessageResponse::class);
        $this->options = new ClientOptions();

        $this->subject = new ClientSearchHandler(
            $this->mockQueue,
            $this->options,
        );
    }

    public function test_it_should_send_a_request_and_get_a_response(): void
    {
        $request = Operations::search(new EqualityFilter('foo', 'bar'));
        $message = new LdapMessageRequest(1, $request);

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($message);

        $this->mockQueue
            ->expects($this->once())
            ->method('getMessage')
            ->with(1)
            ->willReturn($this->mockResponse);;

        self::assertSame(
            $this->mockResponse,
            $this->subject->handleRequest($message),
        );
    }

    public function test_it_should_set_a_default_DN_for_a_request_that_has_none(): void
    {
        $this->options->setBaseDn('cn=foo');
        $mockMessage = $this->createMock(LdapMessageRequest::class);
        $mockRequest = $this->createMock(SearchRequest::class);

        $this->mockQueue
            ->expects($this->once())
            ->method('getMessage')
            ->with(1)
            ->willReturn($this->mockResponse);

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($mockMessage);

        $mockMessage
            ->method('getMessageId')
            ->willReturn(1);
        $mockMessage
            ->method('getRequest')
            ->willReturn($mockRequest);
        $mockRequest
            ->method('getBaseDn')
            ->willReturn(null);

        $mockRequest
            ->expects($this->once())
            ->method('setBaseDn')
            ->with('cn=foo');

        $this->subject->handleRequest($mockMessage);
    }

    public function test_it_should_not_keep_getting_messages_when_the_first_result_is_search_done(): void
    {
        $messageTo = new LdapMessageRequest(1, new SearchRequest(new EqualityFilter('foo', 'bar')));
        $response = new LdapMessageResponse(1, new SearchResultDone(0));

        $this->mockQueue
            ->expects($this->never())
            ->method('getMessage');

        self::assertInstanceOf(
            SearchResponse::class,
            $this->subject->handleResponse(
                $messageTo,
                $response,
            )?->getResponse()
        );
    }

    public function test_it_should_retrieve_results_until_it_receives_a_search_done_and_return_all_results(): void
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

        $this->mockQueue
            ->method('getMessage')
            ->will($this->onConsecutiveCalls(
                new LdapMessageResponse(1, $entries[0]),
                new LdapMessageResponse(1, $entries[1]),
                new LdapMessageResponse(1, $referrals[0]),
                new LdapMessageResponse(1, $entries[2]),
                new LdapMessageResponse(1, new SearchResultDone(
                    0,
                    'cn=foo',
                    'bar'
                ))
            ));

        $this->mockQueue
            ->expects($this->exactly(5))
            ->method('getMessage')
            ->with(1);


        self::assertEquals(
            self::makeSearchResponseFromEntries(
                dn: 'cn=foo',
                diagnostic: 'bar',
                searchEntryResults: [
                    new SearchResultEntry(new Entry('bar')),
                    ...$entries,
                ],
                searchReferralResults: $referrals,
            ),
            $this->subject->handleResponse(
                $messageTo,
                $response,
            ),
        );
    }

    public function test_it_should_throw_an_exception_if_the_result_code_is_not_success(): void
    {
        $messageTo = new LdapMessageRequest(1, new SearchRequest(new EqualityFilter('foo', 'bar')));
        $response = new LdapMessageResponse(1, new SearchResultDone(ResultCode::SIZE_LIMIT_EXCEEDED));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::SIZE_LIMIT_EXCEEDED);

        $this->subject->handleResponse(
            $messageTo,
            $response,
        );
    }
}
