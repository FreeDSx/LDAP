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
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\Paging;
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
        RequestContext $context,
        Paging $paging
    ) {
        $request = new SearchRequest(Filters::equal('cn', 'foo'));
        $entries = new Entries(new Entry('cn=foo,dc=foo,dc=bar'));
        $client->paging($request, Argument::any())
            ->shouldBeCalled()
            ->willReturn($paging);

        $paging->isCritical(false)
            ->shouldBeCalled()
            ->willReturn($paging);
        $paging->getEntries(25)->shouldBeCalled()
            ->willReturn($entries);
        $paging->hasEntries()->shouldBeCalled()
            ->willReturn(true);
        $paging->sizeEstimate()->shouldBeCalled()
            ->willReturn(25);

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
        RequestContext $context,
        Paging $paging
    ) {
        $request = new SearchRequest(Filters::equal('cn', 'foo'));
        $entries = new Entries(new Entry('cn=foo,dc=foo,dc=bar'));
        $client->paging($request, Argument::any())
            ->shouldBeCalled()
            ->willReturn($paging);

        $paging->isCritical(false)
            ->shouldBeCalled()
            ->willReturn($paging);
        $paging->getEntries(25)->shouldBeCalled()
            ->willReturn($entries);
        $paging->hasEntries()->shouldBeCalled()
            ->willReturn(false);

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
