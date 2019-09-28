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
use FreeDSx\Ldap\Operation\Response\ModifyDnResponse;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\DirSync;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\Paging;
use FreeDSx\Ldap\Search\RangeRetrieval;
use FreeDSx\Ldap\Search\Vlv;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class LdapClientSpec extends ObjectBehavior
{
    function let(ClientProtocolHandler $handler)
    {
        $handler->isConnected()->willReturn(false);
        $this->setProtocolHandler($handler);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(LdapClient::class);
    }

    function it_should_send_a_message_and_throw_an_exception_if_no_response_is_received_on_sendAndReceive(ClientProtocolHandler $handler)
    {
        $handler->send(Argument::any())->shouldBeCalled()->willReturn(null);

        $this->shouldThrow(OperationException::class)->during('sendAndReceive', [Operations::read('')]);
    }

    function it_should_send_a_message_and_return_the_response_on_sendAndReceive(ClientProtocolHandler $handler, LdapMessageResponse $response)
    {
        $handler->send(Argument::any())->shouldBeCalled()->willReturn($response);

        $this->sendAndReceive(Operations::read(''))->shouldBeEqualTo($response);
    }

    function it_should_send_a_search_and_get_entries_back(ClientProtocolHandler $handler)
    {
        $search = Operations::search(Filters::equal('foo', 'bar'));

        $handler->send($search)->shouldBeCalled()->willReturn(new LdapMessageResponse(1, new SearchResponse(new LdapResult(0, ''), new Entries(Entry::create('dc=foo,dc=bar')))));

        $this->search($search)->shouldBeLike(new Entries(Entry::create('dc=foo,dc=bar')));
    }

    function it_should_bind(ClientProtocolHandler $handler)
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

    function it_should_construct_a_dirsync_helper()
    {
        $this->dirSync()->shouldBeAnInstanceOf(DirSync::class);
    }

    function it_should_construct_a_range_retrieval_helper()
    {
        $this->range()->shouldBeAnInstanceOf(RangeRetrieval::class);    
    }
    
    function it_should_start_tls(ClientProtocolHandler $handler)
    {
        $handler->send(Operations::extended(ExtendedRequest::OID_START_TLS))->shouldBeCalled()->willReturn(null);

        $this->startTls();
    }

    function it_should_unbind_if_requested(ClientProtocolHandler $handler)
    {
        $handler->send(new UnbindRequest())->shouldBeCalled()->willReturn(null);

        $this->unbind();
    }

    function it_should_return_a_whoami(ClientProtocolHandler $handler)
    {
        $handler->send(Operations::extended(ExtendedRequest::OID_WHOAMI))->willReturn(new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(0, ''), null, 'foo')));

        $this->whoami()->shouldBeEqualTo('foo');
    }

    function it_should_return_a_correct_compare_response_on_a_match(ClientProtocolHandler $handler)
    {
        $handler->send(Operations::compare('cn=foo', 'foo', 'bar'))->willReturn(new LdapMessageResponse(1, new CompareResponse(ResultCode::COMPARE_TRUE)));

        $this->compare('cn=foo', 'foo', 'bar')->shouldBeEqualTo(true);
    }

    function it_should_return_a_correct_compare_response_on_a_non_match(ClientProtocolHandler $handler)
    {
        $handler->send(Operations::compare('cn=foo', 'foo', 'bar'))->willReturn(new LdapMessageResponse(1, new CompareResponse(ResultCode::COMPARE_FALSE)));

        $this->compare('cn=foo', 'foo', 'bar')->shouldBeEqualTo(false);
    }

    function it_should_send_a_modify_operation_on_update(ClientProtocolHandler $handler)
    {
        $entry = Entry::create('cn=foo,dc=local', ['cn' => 'foo']);
        $entry->set('sn', 'bar');
        $handler->send(Operations::modify($entry->getDn(), ...$entry->changes()))->shouldBeCalled()
            ->willReturn(new LdapMessageResponse(1, new ModifyResponse(ResultCode::SUCCESS)));

        $this->update($entry);
    }

    function it_should_send_an_add_operation_on_create(ClientProtocolHandler $handler)
    {
        $entry = Entry::create('cn=foo,dc=local', ['cn' => 'foo']);
        $handler->send(Operations::add($entry))->shouldBeCalled()
            ->willReturn(new LdapMessageResponse(1, new AddResponse(ResultCode::SUCCESS)));

        $this->create($entry);
    }

    function it_should_send_a_delete_operation_on_delete(ClientProtocolHandler $handler)
    {
        $entry = new Entry('cn=foo,dc=local');
        $handler->send(Operations::delete('cn=foo,dc=local'))->shouldBeCalled()
            ->willReturn(new LdapMessageResponse(1, new DeleteResponse(ResultCode::SUCCESS)));

        $this->delete($entry);
    }

    function it_should_send_a_modify_dn_operation_on_move(ClientProtocolHandler $handler)
    {
        $entry = new Entry('cn=foo,dc=local');
        $parent = new Entry('cn=bar,dc=local');

        $handler->send(Operations::move('cn=foo,dc=local', 'cn=bar,dc=local'))->shouldBeCalled()
            ->willReturn(new LdapMessageResponse(1, new ModifyDnResponse(ResultCode::SUCCESS)));

        $this->move($entry, $parent);
    }

    function it_should_send_a_modify_dn_operation_on_rename(ClientProtocolHandler $handler)
    {
        $entry = new Entry('cn=foo,dc=local');
        $newRdn = 'cn=bar';

        $handler->send(Operations::rename('cn=foo,dc=local', 'cn=bar'))->shouldBeCalled()
            ->willReturn(new LdapMessageResponse(1, new ModifyDnResponse(ResultCode::SUCCESS)));

        $this->rename($entry, $newRdn);
    }

    function it_should_send_a_base_search_on_a_read_and_return_an_entry(ClientProtocolHandler $handler)
    {
        $entry = new Entry('cn=foo,dc=local');
        $handler->send(Operations::read('cn=foo,dc=local'))->shouldBeCalled()
            ->willReturn(new LdapMessageResponse(1, new SearchResponse(new LdapResult(ResultCode::SUCCESS), new Entries(
                $entry
            ))));

        $this->read($entry)->shouldBeEqualTo($entry);
    }

    function it_should_send_a_read_to_the_RootDSE_if_it_is_called_with_no_arguments(ClientProtocolHandler $handler)
    {
        $entry = new Entry('');
        $handler->send(Operations::read(''))->shouldBeCalled()
            ->willReturn(new LdapMessageResponse(1, new SearchResponse(new LdapResult(ResultCode::SUCCESS), new Entries(
                $entry
            ))));

        $this->read()->shouldBeEqualTo($entry);
    }

    function it_should_send_a_base_search_on_a_read_and_return_null_if_it_does_not_exist(ClientProtocolHandler $handler)
    {
        $entry = new Entry('cn=foo,dc=local');
        $handler->send(Operations::read('cn=foo,dc=local'))->shouldBeCalled()
            ->willThrow(new OperationException('', ResultCode::NO_SUCH_OBJECT));

        $this->read($entry)->shouldBeNull();
    }

    function it_should_throw_an_exception_on_read_or_fail_if_the_entry_does_not_exist(ClientProtocolHandler $handler)
    {
        $exception = new OperationException('', ResultCode::NO_SUCH_OBJECT);
        $entry = new Entry('cn=foo,dc=local');
        $handler->send(Operations::read('cn=foo,dc=local'))->shouldBeCalled()
            ->willThrow($exception);

        $this->shouldThrow($exception)->during('readOrFail', [$entry]);
    }

    function it_should_return_an_entry_on_a_readOrFail_if_it_exists(ClientProtocolHandler $handler)
    {
        $entry = new Entry('cn=foo,dc=local');
        $handler->send(Operations::read('cn=foo,dc=local'))->shouldBeCalled()
            ->willReturn(new LdapMessageResponse(1, new SearchResponse(new LdapResult(ResultCode::SUCCESS), new Entries(
                $entry
            ))));

        $this->readOrFail($entry)->shouldBeEqualTo($entry);
    }

    function it_should_send_a_base_search_on_a_read_and_throw_an_unrelated_operation_exception(ClientProtocolHandler $handler)
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
            'servers' => [],
            'port' => 389,
            'base_dn' => null,
            'page_size' => 1000,
            'use_ssl' => false,
            'ssl_validate_cert' => true,
            'ssl_allow_self_signed' => null,
            'ssl_ca_cert' => null,
            'ssl_peer_name' => null,
            'timeout_connect' => 3,
            'timeout_read' => 10,
            'referral' => 'throw',
            'referral_chaser' => null,
            'referral_limit' => 10,
        ]);
    }

    function it_should_set_the_options()
    {
        $this->setOptions(['servers' => ['bar', 'foo']]);

        $this->getOptions()->shouldHaveKeyWithValue('servers', ['bar', 'foo']);
    }
}
