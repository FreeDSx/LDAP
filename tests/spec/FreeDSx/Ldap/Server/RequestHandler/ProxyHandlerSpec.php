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
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\ProxyHandler;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ProxyHandlerSpec extends ObjectBehavior
{
    public function let(
        LdapClient $client,
        RequestContext $context
    ) {
        $context->controls()->willReturn(new ControlBag());
        $context->token()->willReturn(new BindToken('foo', 'bar'));

        $this->beConstructedWith($client);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(ProxyHandler::class);
    }

    public function it_should_implement_request_handler_interface()
    {
        $this->shouldImplement(RequestHandlerInterface::class);
    }

    public function it_should_implement_root_dse_handler_interface()
    {
        $this->shouldImplement(RootDseHandlerInterface::class);
    }

    public function it_should_handle_a_root_dse_request(
        LdapClient $client,
        RequestContext $context,
        SearchRequest $request
    ) {
        $rootDse = new Entry('');
        $client->search($request, Argument::any())
            ->shouldBeCalled()
            ->willReturn(new Entries($rootDse));

        $this->rootDse($context,$request, new Entry(''))->shouldBeEqualTo($rootDse);
    }

    public function it_should_handle_a_root_dse_request_when_non_is_returned(
        LdapClient $client,
        RequestContext $context,
        SearchRequest $request
    ) {
        $client->search($request, Argument::any())
            ->shouldBeCalled()
            ->willReturn(new Entries());

        $this->shouldThrow(new OperationException('Entry not found.', ResultCode::NO_SUCH_OBJECT))
            ->during('rootDse', [$context,$request, new Entry('')]);
    }
}
