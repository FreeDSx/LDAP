<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap;

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\Response\AddResponse;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\CompareResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\Paging;
use FreeDSx\Ldap\Search\Vlv;
use PhpSpec\ObjectBehavior;

class LdapClientSpec extends ObjectBehavior
{
    function let(ClientProtocolHandler $handler)
    {
        $handler->getSocket()->willReturn(null);
        $this->beConstructedWith(['servers' => ['foo']]);
        $this->setProtocolHandler($handler);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(LdapClient::class);
    }

    function it_should_send_a_search_and_get_entries_back($handler)
    {
        $search = Operations::search(Filters::equal('foo', 'bar'));

        $handler->send($search)->shouldBeCalled()->willReturn(new LdapMessageResponse(1, new SearchResponse(new LdapResult(0, ''), new Entries(Entry::create('dc=foo,dc=bar')))));

        $this->search($search)->shouldBeLike(new Entries(Entry::create('dc=foo,dc=bar')));
    }

    function it_should_bind($handler)
    {
        $response = new LdapMessageResponse(1, new BindResponse(new LdapResult(0, '')));
        $handler->send(new SimpleBindRequest('foo', 'bar', 3))->shouldBeCalled()->willReturn($response);

        $this->bind('foo', 'bar')->shouldBeEqualTo($response);
    }

    function it_should_construct_a_pager_helper()
    {
        $this->paging(Operations::search(Filters::equal('foo', 'bar')))->shouldBeAnInstanceOf(Paging::class);
    }

    function it_should_construct_a_vlv_helper()
    {
        $this->vlv(Operations::search(Filters::equal('foo', 'bar')), 'cn', 100)->shouldBeAnInstanceOf(Vlv::class);
    }

    function it_should_start_tls($handler)
    {
        $handler->send(Operations::extended(ExtendedRequest::OID_START_TLS))->shouldBeCalled()->willReturn(null);

        $this->startTls();
    }

    function it_should_unbind_if_requested($handler)
    {
        $handler->send(new UnbindRequest())->shouldBeCalled()->willReturn(null);

        $this->unbind();
    }

    function it_should_return_a_whoami($handler)
    {
        $handler->send(Operations::extended(ExtendedRequest::OID_WHOAMI))->willReturn(new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(0, ''), null, 'foo')));

        $this->whoami()->shouldBeEqualTo('foo');
    }

    function it_should_return_a_correct_compare_response_on_a_match($handler)
    {
        $handler->send(Operations::compare('cn=foo', 'foo', 'bar'))->willReturn(new LdapMessageResponse(1, new CompareResponse(ResultCode::COMPARE_TRUE)));

        $this->compare('cn=foo', 'foo', 'bar')->shouldBeEqualTo(true);
    }

    function it_should_return_a_correct_compare_response_on_a_non_match($handler)
    {
        $handler->send(Operations::compare('cn=foo', 'foo', 'bar'))->willReturn(new LdapMessageResponse(1, new CompareResponse(ResultCode::COMPARE_FALSE)));

        $this->compare('cn=foo', 'foo', 'bar')->shouldBeEqualTo(false);
    }

    function it_should_send_a_modify_operation_on_update($handler)
    {
        $entry = Entry::create('cn=foo,dc=local', ['cn' => 'foo']);
        $entry->set('sn', 'bar');
        $handler->send(Operations::modify($entry->getDn(), ...$entry->changes()))->shouldBeCalled()
            ->willReturn(new LdapMessageResponse(1, new ModifyResponse(ResultCode::SUCCESS)));

        $this->update($entry);
    }

    function it_should_send_an_add_operation_on_create($handler)
    {
        $entry = Entry::create('cn=foo,dc=local', ['cn' => 'foo']);
        $handler->send(Operations::add($entry))->shouldBeCalled()
            ->willReturn(new LdapMessageResponse(1, new AddResponse(ResultCode::SUCCESS)));

        $this->create($entry);
    }

    function it_should_send_a_delete_operation_on_delete($handler)
    {
        $entry = new Entry('cn=foo,dc=local');
        $handler->send(Operations::delete('cn=foo,dc=local'))->shouldBeCalled()
            ->willReturn(new LdapMessageResponse(1, new DeleteResponse(ResultCode::SUCCESS)));

        $this->delete($entry);
    }

    function it_should_send_a_base_search_on_a_read_and_return_an_entry($handler)
    {
        $entry = new Entry('cn=foo,dc=local');
        $handler->send(Operations::read('cn=foo,dc=local'))->shouldBeCalled()
            ->willReturn(new LdapMessageResponse(1, new SearchResponse(new LdapResult(ResultCode::SUCCESS), new Entries(
                $entry
            ))));

        $this->read($entry)->shouldBeEqualTo($entry);
    }

    function it_should_send_a_base_search_on_a_read_and_return_null_if_it_does_not_exist($handler)
    {
        $entry = new Entry('cn=foo,dc=local');
        $handler->send(Operations::read('cn=foo,dc=local'))->shouldBeCalled()
            ->willThrow(new OperationException('', ResultCode::NO_SUCH_OBJECT));

        $this->read($entry)->shouldBeNull();
    }

    function it_should_send_a_base_search_on_a_read_and_throw_an_unrelated_operation_exception($handler)
    {
        $entry = new Entry('cn=foo,dc=local');
        $handler->send(Operations::read('cn=foo,dc=local'))->shouldBeCalled()
            ->willThrow(new OperationException('', ResultCode::INSUFFICIENT_ACCESS_RIGHTS));

        $this->shouldThrow(OperationException::class)->during('read', [$entry]);
    }

    function it_should_get_the_options()
    {
        $this->getOptions()->shouldBeEqualTo([
            'version' => 3,
            'servers' => ['foo'],
            'port' => 389,
            'base_dn' => null,
            'page_size' => 1000,
            'use_ssl' => false,
            'use_tls' => false,
            'ssl_validate_cert' => true,
            'ssl_allow_self_signed' => null,
            'ssl_ca_cert' => null,
            'ssl_peer_name' => null,
            'timeout_connect' => 3,
            'timeout_read' => 10,
            'referral' => 'throw',
            'referral_chaser' => null,
            'referral_limit' => 10,
            'logger' => null,
        ]);
    }

    function it_should_set_the_options()
    {
        $this->setOptions(['servers' => ['bar', 'foo']]);

        $this->getOptions()->shouldHaveKeyWithValue('servers', ['bar', 'foo']);
    }
}
