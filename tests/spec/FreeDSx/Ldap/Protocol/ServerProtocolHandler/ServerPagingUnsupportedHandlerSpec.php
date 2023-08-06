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

namespace spec\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

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
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ServerPagingUnsupportedHandlerSpec extends ObjectBehavior
{
    public function let(ServerQueue $queue): void
    {
        $this->beConstructedWith($queue);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ServerPagingUnsupportedHandler::class);
    }

    public function it_should_send_a_search_request_to_the_request_handler_if_paging_is_not_critical(
        ServerQueue $queue,
        RequestHandlerInterface $handler,
        TokenInterface $token
    ): void {
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

        $handler->search(Argument::any(), $search->getRequest())
            ->shouldBeCalled()
            ->willReturn($entries);

        $queue->sendMessage(
            $resultEntry1,
            $resultEntry2,
            new LdapMessageResponse(
                2,
                new SearchResultDone(
                    0,
                    'dc=foo,dc=bar'
                )
            )
        )->shouldBeCalled();

        $this->handleRequest(
            $search,
            $token,
            $handler,
        );
    }

    public function it_should_throw_an_unavailable_critical_extension_if_paging_is_marked_critical(
        ServerQueue $queue,
        RequestHandlerInterface $handler,
        TokenInterface $token
    ): void {
        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))->base('dc=foo,dc=bar'),
            (new PagingControl(10, ''))->setCriticality(true)
        );

        $handler->search(Argument::any(), $search->getRequest())
            ->shouldNotBeCalled();

        $this->shouldThrow(new OperationException('The server does not support the paging control.', ResultCode::UNAVAILABLE_CRITICAL_EXTENSION))->during('handleRequest', [
            $search,
            $token,
            $handler,
            $queue,
            new ServerOptions()
        ]);
    }

    public function it_should_send_a_SearchResultDone_with_an_operation_exception_thrown_from_the_handler(
        ServerQueue $queue,
        RequestHandlerInterface $handler,
        TokenInterface $token
    ): void {
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

        $handler->search(Argument::any(), Argument::any())
            ->willThrow(new OperationException(
                "Fail",
                ResultCode::OPERATIONS_ERROR
            ));

        $queue->sendMessage(new LdapMessageResponse(
            2,
            new SearchResultDone(
                ResultCode::OPERATIONS_ERROR,
                'dc=foo,dc=bar',
                "Fail"
            )
        ))->shouldBeCalled()
            ->willReturn($queue);

        $this->handleRequest(
            $search,
            $token,
            $handler,
        );
    }
}
