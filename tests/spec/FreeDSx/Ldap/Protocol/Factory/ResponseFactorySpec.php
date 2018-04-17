<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Response\AddResponse;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\CompareResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\ModifyDnResponse;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Search\Filters;
use PhpSpec\ObjectBehavior;

class ResponseFactorySpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ResponseFactory::class);
    }

    function it_should_get_a_bind_response()
    {
        $this::get(new SimpleBindRequest('foo', 'bar'), 0, 'foo')->shouldBeLike(new BindResponse(new LdapResult(0, '', 'foo')));
    }

    function it_should_get_an_add_response()
    {
        $this::get(new AddRequest(Entry::create('foo')), 0, 'foo')->shouldBeLike(new AddResponse(0, 'foo', 'foo'));
    }

    function it_should_get_a_compare_response()
    {
        $this::get(new CompareRequest('foo', Filters::equal('foo', 'bar')), ResultCode::COMPARE_TRUE, 'foo')->shouldBeLike(new CompareResponse(ResultCode::COMPARE_TRUE, 'foo', 'foo'));
    }

    function it_should_get_a_modify_response()
    {
        $this::get(new ModifyRequest('foo', Change::add('foo', 'bar')), 0, 'foo')->shouldBeLike(new ModifyResponse(0, 'foo', 'foo'));
    }

    function it_should_get_a_modify_dn_response()
    {
        $this::get(new ModifyDnRequest('foo', 'cn=bar', true), 0, 'foo')->shouldBeLike(new ModifyDnResponse(0, 'foo', 'foo'));
    }

    function it_should_get_an_extended_response()
    {
        $this::get(new ExtendedRequest('foo', 'bar'), 0, 'foo')->shouldBeLike(new ExtendedResponse(new LdapResult(0, '', 'foo')));
    }

    function it_should_get_a_delete_response()
    {
        $this::get(new DeleteRequest('foo'), 0, 'foo')->shouldBeLike(new DeleteResponse(0, 'foo', 'foo'));
    }

    function it_should_get_a_search_response()
    {
        $this::get(new SearchRequest(Filters::present('objectClass', 'cn')), 0, 'foo')->shouldBeLike(new SearchResultDone(0, '', 'foo'));
    }
}
