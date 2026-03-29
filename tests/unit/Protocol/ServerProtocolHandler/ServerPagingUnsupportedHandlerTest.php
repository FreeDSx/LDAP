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
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPagingUnsupportedHandler;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\SearchResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerPagingUnsupportedHandlerTest extends TestCase
{
    private ServerPagingUnsupportedHandler $subject;

    private ServerQueue&MockObject $mockQueue;

    private RequestHandlerInterface&MockObject $mockRequestHandler;

    private TokenInterface&MockObject $mockToken;

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockRequestHandler = $this->createMock(RequestHandlerInterface::class);

        $this->subject = new ServerPagingUnsupportedHandler(
            $this->mockQueue,
            $this->mockRequestHandler,
        );
    }

    public function test_it_should_send_a_search_request_to_the_request_handler_if_paging_is_not_critical(): void
    {
        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))->base('dc=foo,dc=bar'),
            (new PagingControl(10, ''))->setCriticality(false)
        );

        $entries = new Entries(Entry::create('dc=foo,dc=bar', ['cn' => 'foo']), Entry::create('dc=bar,dc=foo', ['cn' => 'bar']));
        $resultEntry1 = new LdapMessageResponse(
            2,
            new SearchResultEntry(Entry::create('dc=foo,dc=bar', ['cn' => 'foo']))
        );
        $resultEntry2 = new LdapMessageResponse(
            2,
            new SearchResultEntry(Entry::create('dc=bar,dc=foo', ['cn' => 'bar']))
        );

        $this->mockRequestHandler
            ->expects($this->once())
            ->method('search')
            ->with(self::anything(), $search->getRequest())
            ->willReturn(SearchResult::make($entries));

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                $resultEntry1,
                $resultEntry2,
                new LdapMessageResponse(
                    2,
                    new SearchResultDone(
                        0,
                        'dc=foo,dc=bar'
                    )
                ),
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    public function test_it_should_throw_an_unavailable_critical_extension_if_paging_is_marked_critical(): void
    {
        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))->base('dc=foo,dc=bar'),
            (new PagingControl(10, ''))->setCriticality(true)
        );

        $this->mockRequestHandler
            ->expects($this->never())
            ->method('search')
            ->with(self::anything(), $search->getRequest());

        self::expectExceptionObject(
            new OperationException(
                'The server does not support the paging control.',
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
            ),
        );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    public function test_it_should_send_a_SearchResultDone_with_an_operation_exception_thrown_from_the_handler(): void
    {
        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal(
                'foo',
                'bar'
            )))->base('dc=foo,dc=bar'),
            new PagingControl(
                10,
                ''
            )
        );

        $this->mockRequestHandler
            ->method('search')
            ->willThrowException(
                new OperationException(
                    'Fail',
                    ResultCode::OPERATIONS_ERROR
                )
            );

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(self::equalTo(new LdapMessageResponse(
                2,
                new SearchResultDone(
                    ResultCode::OPERATIONS_ERROR,
                    'dc=foo,dc=bar',
                    "Fail"
                )
            )));

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }
}
