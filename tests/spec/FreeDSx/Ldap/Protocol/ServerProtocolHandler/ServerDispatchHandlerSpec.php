<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerDispatchHandler;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ServerDispatchHandlerSpec extends ObjectBehavior
{
    public function let(ServerQueue $queue)
    {
        $queue->sendMessage(Argument::any())->willReturn($queue);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ServerDispatchHandler::class);
    }

    function it_should_send_an_add_request_to_the_request_handler(ServerQueue $queue, RequestHandlerInterface $handler, TokenInterface $token)
    {
        $add = new LdapMessageRequest(1, new AddRequest(Entry::create('cn=foo,dc=bar')));

        $handler->add(Argument::any(), $add->getRequest())->shouldBeCalled();
        $this->handleRequest($add, $token, $handler, $queue, []);
    }

    function it_should_send_a_delete_request_to_the_request_handler(ServerQueue $queue, RequestHandlerInterface $handler, TokenInterface $token)
    {
        $delete = new LdapMessageRequest(1, new DeleteRequest('cn=foo,dc=bar'));

        $handler->delete(Argument::any(), $delete->getRequest())->shouldBeCalled();
        $this->handleRequest($delete, $token, $handler, $queue, []);
    }

    function it_should_send_a_modify_request_to_the_request_handler(ServerQueue $queue, RequestHandlerInterface $handler, TokenInterface $token)
    {
        $modify = new LdapMessageRequest(1, new ModifyRequest('cn=foo,dc=bar', Change::add('foo', 'bar')));

        $handler->modify(Argument::any(), $modify->getRequest())->shouldBeCalled();
        $this->handleRequest($modify, $token, $handler, $queue, []);
    }

    function it_should_send_a_modify_dn_request_to_the_request_handler(ServerQueue $queue, RequestHandlerInterface $handler, TokenInterface $token)
    {
        $modifyDn = new LdapMessageRequest(1, new ModifyDnRequest('cn=foo,dc=bar', 'cn=bar', true));

        $handler->modifyDn(Argument::any(), $modifyDn->getRequest())->shouldBeCalled();
        $this->handleRequest($modifyDn, $token, $handler, $queue, []);
    }

    function it_should_send_an_extended_request_to_the_request_handler(ServerQueue $queue, RequestHandlerInterface $handler, TokenInterface $token)
    {
        $ext = new LdapMessageRequest(1, new ExtendedRequest('foo', 'bar'));

        $handler->extended(Argument::any(), $ext->getRequest())->shouldBeCalled();
        $this->handleRequest($ext, $token, $handler, $queue, []);
    }

    function it_should_send_a_compare_request_to_the_request_handler(ServerQueue $queue, RequestHandlerInterface $handler, TokenInterface $token)
    {
        $compare = new LdapMessageRequest(1, new CompareRequest('cn=foo,dc=bar', Filters::equal('foo', 'bar')));

        $handler->compare(Argument::any(), $compare->getRequest())->shouldBeCalled()->willReturn(true);
        $this->handleRequest($compare, $token, $handler, $queue, []);
    }

    function it_should_throw_an_operation_exception_if_the_request_is_unsupported(ServerQueue $queue, RequestHandlerInterface $handler, TokenInterface $token)
    {
        $request  = new LdapMessageRequest(2, new AbandonRequest(1));

        $this->shouldThrow(OperationException::class)->during(
            'handleRequest',
            [$request, $token, $handler, $queue, []]
        );
    }
}
