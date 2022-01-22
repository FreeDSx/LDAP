<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\ProxyPagingHandler;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ProxyPagingHandlerSpec extends ObjectBehavior
{
    public function let(LdapClient $client, RequestContext $context)
    {
        $context->controls()->willReturn(new ControlBag());

        $this->beConstructedWith($client);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(ProxyPagingHandler::class);
    }

    public function it_should_implement_paging_handler_interface()
    {
        $this->shouldImplement(PagingHandlerInterface::class);
    }

    public function it_should_handle_a_paging_request_when_paging_is_stil_going(
        LdapClient $client,
        RequestContext $context
    ) {
        $request = new SearchRequest(Filters::equal('cn', 'foo'));
        $entries = new Entries(new Entry('cn=foo,dc=foo,dc=bar'));
        $client->sendAndReceive($request, Argument::any())
            ->shouldBeCalled()
            ->willReturn(new LdapMessageResponse(
                2,
                new SearchResponse(
                    new LdapResult(0),
                    $entries
                ),
                new PagingControl(25, 'foo')
            ));

        $pagingRequest = new PagingRequest(
            new PagingControl(25, ''),
            $request,
            new ControlBag(),
            'foo'
        );

        $this->page($pagingRequest, $context)->isComplete()->shouldBeEqualTo(false);
        $this->page($pagingRequest, $context)->getEntries()->shouldBeEqualTo($entries);
        $this->page($pagingRequest, $context)->getRemaining()->shouldBeEqualTo(25);
    }

    public function it_should_handle_a_paging_request_when_paging_is_complete(
        LdapClient $client,
        RequestContext $context
    ) {
        $request = new SearchRequest(Filters::equal('cn', 'foo'));
        $entries = new Entries(new Entry('cn=foo,dc=foo,dc=bar'));
        $client->sendAndReceive($request, Argument::any())
            ->shouldBeCalled()
            ->willReturn(new LdapMessageResponse(
                2,
                new SearchResponse(
                    new LdapResult(0),
                    $entries
                ),
                new PagingControl(0, '')
            ));

        $pagingRequest = new PagingRequest(
            new PagingControl(25, ''),
            $request,
            new ControlBag(),
            'foo'
        );

        $this->page($pagingRequest, $context)->isComplete()->shouldBeEqualTo(true);
        $this->page($pagingRequest, $context)->getEntries()->shouldBeEqualTo($entries);
        $this->page($pagingRequest, $context)->getRemaining()->shouldBeEqualTo(0);
    }

    public function it_should_handle_a_paging_request_when_paging_is_not_returned_from_the_proxy(
        LdapClient $client,
        RequestContext $context
    ) {
        $request = new SearchRequest(Filters::equal('cn', 'foo'));
        $entries = new Entries(new Entry('cn=foo,dc=foo,dc=bar'));
        $client->sendAndReceive($request, Argument::any())
            ->shouldBeCalled()
            ->willReturn(new LdapMessageResponse(
                2,
                new SearchResponse(
                    new LdapResult(0),
                    $entries
                )
            ));

        $pagingRequest = new PagingRequest(
            new PagingControl(25, ''),
            $request,
            new ControlBag(),
            'foo'
        );

        $this->page($pagingRequest, $context)->isComplete()->shouldBeEqualTo(true);
        $this->page($pagingRequest, $context)->getEntries()->shouldBeEqualTo($entries);
        $this->page($pagingRequest, $context)->getRemaining()->shouldBeEqualTo(0);
    }
}
