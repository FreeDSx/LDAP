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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use PhpSpec\ObjectBehavior;

class GenericRequestHandlerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(GenericRequestHandler::class);
    }

    function it_should_implement_request_handler_interface()
    {
        $this->shouldImplement(RequestHandlerInterface::class);
    }

    function it_should_throw_an_operations_exception_on_an_add_request(RequestContext $context, AddRequest $request)
    {
        $this->shouldThrow(OperationException::class)->during('add', [$context, $request]);
    }

    function it_should_throw_an_operations_exception_on_a_delete_request(RequestContext $context, DeleteRequest $request)
    {
        $this->shouldThrow(OperationException::class)->during('delete', [$context, $request]);
    }

    function it_should_throw_an_operations_exception_on_a_modify_request(RequestContext $context, ModifyRequest $request)
    {
        $this->shouldThrow(OperationException::class)->during('modify', [$context, $request]);
    }

    function it_should_throw_an_operations_exception_on_a_modify_dn_request(RequestContext $context, ModifyDnRequest $request)
    {
        $this->shouldThrow(OperationException::class)->during('modifyDn', [$context, $request]);
    }

    function it_should_throw_an_operations_exception_on_a_search_request(RequestContext $context, SearchRequest $request)
    {
        $this->shouldThrow(OperationException::class)->during('search', [$context, $request]);
    }

    function it_should_throw_an_operations_exception_on_a_compare_request(RequestContext $context, CompareRequest $request)
    {
        $this->shouldThrow(OperationException::class)->during('compare', [$context, $request]);
    }

    function it_should_throw_an_operations_exception_on_an_extended_request(RequestContext $context, ExtendedRequest $request)
    {
        $request->getName()->willReturn('foo');

        $this->shouldThrow(OperationException::class)->during('extended', [$context, $request]);
    }

    function it_should_return_false_on_a_bind_request()
    {
        $this->bind('foo', 'bar')->shouldBeEqualTo(false);
    }
}
