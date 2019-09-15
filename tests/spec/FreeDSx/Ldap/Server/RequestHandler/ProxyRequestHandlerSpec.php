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
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\CompareResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\ProxyRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use PhpSpec\ObjectBehavior;

class ProxyRequestHandlerSpec extends ObjectBehavior
{
    function let(LdapClient $client, RequestContext $context)
    {
        $context->controls()->willReturn(new ControlBag());
        $context->token()->willReturn(new BindToken('foo', 'bar'));
        $this->setLdapClient($client);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ProxyRequestHandler::class);
    }

    function it_should_implement_request_handler_interface()
    {
        $this->shouldImplement(RequestHandlerInterface::class);
    }

    function it_should_send_an_add_request($client, $context)
    {
        $add = Operations::add(Entry::create('cn=foo,dc=freedsx,dc=local'));

        $client->sendAndReceive($add, ...[])->shouldBeCalled();
        $this->add($context, $add);
    }

    function it_should_send_a_delete_request($client, $context)
    {
        $delete = Operations::delete('cn=foo,dc=freedsx,dc=local');

        $client->sendAndReceive($delete, ...[])->shouldBeCalled();
        $this->delete($context, $delete);
    }

    function it_should_send_a_modify_request($client, $context)
    {
        $modify = Operations::modify('cn=foo,dc=freedsx,dc=local', Change::add('foo', 'bar'));

        $client->sendAndReceive($modify, ...[])->shouldBeCalled();
        $this->modify($context, $modify);
    }

    function it_should_send_a_modify_dn_request($client, $context)
    {
        $modifyDn = Operations::rename('cn=foo,dc=freedsx,dc=local', 'cn=bar');

        $client->sendAndReceive($modifyDn, ...[])->shouldBeCalled();
        $this->modifyDn($context, $modifyDn);
    }

    function it_should_send_a_search_request($client, $context)
    {
        $search = Operations::search(Filters::present('objectClass'), 'cn')->base('dc=foo');
        $entries = new Entries(Entry::create('dc=foo'));

        $client->search($search)->shouldBeCalled()->willReturn($entries);
        $this->search($context, $search)->shouldBeEqualTo($entries);
    }

    function it_should_send_a_compare_request_and_return_false_on_no_match($client, $context)
    {
        $compare = Operations::compare('foo', 'foo', 'bar');

        $client->sendAndReceive($compare)->shouldBeCalled()->willReturn(new LdapMessageResponse(1, new CompareResponse(ResultCode::COMPARE_FALSE)));

        $this->compare($context, $compare)->shouldBeEqualTo(false);
    }

    function it_should_send_a_compare_request_and_return_true_on_match($client, $context)
    {
        $compare = Operations::compare('foo', 'foo', 'bar');

        $client->sendAndReceive($compare)->shouldBeCalled()->willReturn(new LdapMessageResponse(1, new CompareResponse(ResultCode::COMPARE_TRUE)));

        $this->compare($context, $compare)->shouldBeEqualTo(true);
    }

    function it_should_send_an_extended_request($client, $context)
    {
        $extended = Operations::extended('foo', 'bar');

        $client->send($extended)->shouldBeCalled();
        $this->extended($context, $extended);
    }

    function it_should_handle_a_bind_request($client)
    {
        $client->bind('foo', 'bar')->shouldBeCalled()->willReturn(new LdapMessageResponse(1, new BindResponse(new LdapResult(0))));

        $this->bind('foo', 'bar')->shouldBeEqualTo(true);
    }

    function it_should_handle_a_bind_request_failure($client)
    {
        $client->bind('foo', 'bar')->shouldBeCalled()->willThrow(new BindException('Foo!', 49));

        $this->shouldThrow(new OperationException('Foo!', 49))->during('bind',['foo', 'bar']);
    }
}
