<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\ModifyDnResponse;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\ProxyRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Tcp\ServerMessageQueue;
use FreeDSx\Ldap\Tcp\Socket;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ServerProtocolHandlerSpec extends ObjectBehavior
{
    function let(Socket $socket, ServerMessageQueue $queue, RequestHandlerInterface $handler)
    {
        $socket->close()->willReturn(null);
        $socket->write(Argument::any())->willReturn($socket);
        $handler->bind('foo', 'bar')->willReturn(true);

        $this->beConstructedWith($socket, [], $queue);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ServerProtocolHandler::class);
    }

    function it_should_handle_an_unbind_request($queue, $socket)
    {
        $queue->getMessage()->willReturn(new LdapMessageRequest(1, new UnbindRequest()));

        $socket->close()->shouldBeCalled();
        $socket->write(Argument::any())->shouldNotBeCalled();

        $this->handle();
    }

    function it_should_handle_a_start_tls_request($queue, $socket)
    {
        $this->beConstructedWith($socket, ['ssl_cert' => 'foo.pem'], $queue);

        $queue->getMessage()->willReturn(new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS)), null);
        $response = (new LdapEncoder())->encode((new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(0), ExtendedRequest::OID_START_TLS)))->toAsn1());
        $socket->write($response)->shouldBeCalled();
        $socket->block(true)->shouldBeCalled();
        $socket->isEncrypted()->willReturn(false);
        $socket->encrypt(true)->shouldBeCalled()->willReturn(true);

        $this->handle();
    }

    function it_should_handle_a_start_tls_request_when_a_cert_is_not_available($queue, $socket)
    {
        $this->beConstructedWith($socket, ['ssl_cert' => null], $queue);

        $queue->getMessage()->willReturn(new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS)), null);
        $response = (new LdapEncoder())->encode((new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(ResultCode::PROTOCOL_ERROR), ExtendedRequest::OID_START_TLS)))->toAsn1());
        $socket->write($response)->shouldBeCalled();
        $socket->encrypt(true)->shouldNotBeCalled();

        $this->handle();
    }

    function it_should_send_an_operations_error_on_a_start_tls_when_the_socket_is_already_encrypted($queue, $socket)
    {
        $this->beConstructedWith($socket, ['ssl_cert' => 'foo.pem'], $queue);
        $queue->getMessage()->willReturn(new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS)), null);

        $response = (new LdapEncoder())->encode((new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(ResultCode::OPERATIONS_ERROR, '', 'The current LDAP session is already encrypted.'), ExtendedRequest::OID_START_TLS)))->toAsn1());
        $socket->write($response)->shouldBeCalled();
        $socket->isEncrypted()->willReturn(true);
        $socket->encrypt(true)->shouldNotBeCalled();

        $this->handle();
    }

    function it_should_handle_a_who_am_i_when_there_is_a_token_with_a_DN_name($queue, $socket, RequestHandlerInterface $handler)
    {
        $this->beConstructedWith($socket, [], $queue);

        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new SimpleBindRequest('cn=foo,dc=foo,dc=nar', 'foo')),
            new LdapMessageRequest(2, new ExtendedRequest(ExtendedRequest::OID_WHOAMI)),
            null
        );
        $handler->bind('cn=foo,dc=foo,dc=nar', 'foo')->shouldBeCalled()->willReturn(true);

        $encoder = new LdapEncoder();
        $socket->write($encoder->encode((new LdapMessageResponse(1, new BindResponse(new LdapResult(0))))->toAsn1()))->shouldBeCalled();
        $socket->write($encoder->encode((new LdapMessageResponse(2, new ExtendedResponse(new LdapResult(0), null,'dn:cn=foo,dc=foo,dc=nar')))->toAsn1()))->shouldBeCalled();

        $this->setRequestHandler($handler);
        $this->handle();
    }

    function it_should_handle_a_who_am_i_when_there_is_a_token_with_a_non_DN_name($socket, $queue, $handler)
    {
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new SimpleBindRequest('foo@bar.local', 'foo')),
            new LdapMessageRequest(2, new ExtendedRequest(ExtendedRequest::OID_WHOAMI)),
            null
        );
        $handler->bind('foo@bar.local', 'foo')->willReturn(true);

        $encoder = new LdapEncoder();
        $socket->write($encoder->encode((new LdapMessageResponse(2, new ExtendedResponse(new LdapResult(0), null,'u:foo@bar.local')))->toAsn1()))->shouldBeCalled();

        $this->setRequestHandler($handler);
        $this->handle();
    }

    function it_should_handle_a_who_am_i_when_there_is_no_token_yet($socket, $queue)
    {
        $queue->getMessage()->willReturn(new LdapMessageRequest(2, new ExtendedRequest(ExtendedRequest::OID_WHOAMI)), null);

        $encoder = new LdapEncoder();
        $socket->write($encoder->encode((new LdapMessageResponse(2, new ExtendedResponse(new LdapResult(0), null, '')))->toAsn1()))->shouldBeCalled();

        $this->handle();
    }

    function it_should_enforce_anonymous_bind_requirements($socket, $queue)
    {
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new AnonBindRequest('foo')),
            null
        );

        $encoder = new LdapEncoder();
        $socket->write($encoder->encode((new LdapMessageResponse(1, new BindResponse(new LdapResult(ResultCode::AUTH_METHOD_UNSUPPORTED, '','Anonymous binds are not allowed.'))))->toAsn1()))->shouldBeCalled();
        $this->handle();
    }

    function it_should_enforce_authentication_requirements($queue, $handler, $socket)
    {
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new ModifyDnRequest('cn=foo,dc=bar', 'cn=bar', true)),
            null
        );

        $encoder = new LdapEncoder();
        $socket->write($encoder->encode((new LdapMessageResponse(1, new ModifyDnResponse(ResultCode::INSUFFICIENT_ACCESS_RIGHTS, 'cn=foo,dc=bar', 'Authentication required.')))->toAsn1()))->shouldBeCalled();
        $handler->modifyDn(Argument::any(), Argument::any())->shouldNotBeCalled();

        $this->setRequestHandler($handler);
        $this->handle();
    }

    function it_should_send_a_notice_of_disconnect_on_a_protocol_exception_from_the_message_queue($socket, $queue)
    {
        $queue->getMessage()->willThrow(new ProtocolException());

        $encoder = new LdapEncoder();
        $socket->write($encoder->encode((new LdapMessageResponse(0, new ExtendedResponse(
            new LdapResult(ResultCode::PROTOCOL_ERROR, '', 'The message encoding is malformed.'),
            ExtendedResponse::OID_NOTICE_OF_DISCONNECTION
        )))->toAsn1()))->shouldBeCalled();

        $this->handle();
    }

    function it_should_send_a_notice_of_disconnect_on_an_encoder_exception_from_the_message_queue($socket, $queue)
    {
        $queue->getMessage()->willThrow(new EncoderException());

        $encoder = new LdapEncoder();
        $socket->write($encoder->encode((new LdapMessageResponse(0, new ExtendedResponse(
            new LdapResult(ResultCode::PROTOCOL_ERROR, '', 'The message encoding is malformed.'),
            ExtendedResponse::OID_NOTICE_OF_DISCONNECTION
        )))->toAsn1()))->shouldBeCalled();

        $this->handle();
    }

    function it_should_not_allow_a_message_with_an_ID_of_zero($socket, $queue)
    {
        $queue->getMessage()->willReturn(new LdapMessageRequest(0, new ExtendedRequest(ExtendedRequest::OID_START_TLS)), null);

        $encoder = new LdapEncoder();
        $socket->write($encoder->encode((new LdapMessageResponse(0, new ExtendedResponse(new LdapResult(
            ResultCode::PROTOCOL_ERROR,
            '',
            'The message ID 0 cannot be used in a client request.'
        ))))->toAsn1()))->shouldBeCalled();

        $this->handle();
    }

    function it_should_not_allow_a_previous_message_ID_from_a_new_request($socket, $queue)
    {
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar')),
            new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_WHOAMI)),
            null
        );
        $encoder = new LdapEncoder();

        $socket->write($encoder->encode((new LdapMessageResponse(0, new ExtendedResponse(new LdapResult(ResultCode::PROTOCOL_ERROR, '', 'The message ID 1 is not valid.'))))->toAsn1()))->shouldBeCalled();
        $this->handle();
    }

    function it_should_send_an_add_request_to_the_request_handler($queue, $handler)
    {
        $add = new AddRequest(Entry::create('cn=foo,dc=bar'));
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar')),
            new LdapMessageRequest(2, $add),
            null
        );

        $handler->add(Argument::any(), $add)->shouldBeCalled();
        $this->setRequestHandler($handler);
        $this->handle();
    }

    function it_should_send_a_delete_request_to_the_request_handler($queue, $handler)
    {
        $delete = new DeleteRequest('cn=foo,dc=bar');
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar')),
            new LdapMessageRequest(2, $delete),
            null
        );

        $handler->delete(Argument::any(), $delete)->shouldBeCalled();
        $this->setRequestHandler($handler);
        $this->handle();
    }

    function it_should_send_a_modify_request_to_the_request_handler($queue, $handler)
    {
        $modify = new ModifyRequest('cn=foo,dc=bar', Change::add('foo', 'bar'));
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar')),
            new LdapMessageRequest(2, $modify),
            null
        );

        $handler->modify(Argument::any(), $modify)->shouldBeCalled();
        $this->setRequestHandler($handler);
        $this->handle();
    }

    function it_should_send_a_modify_dn_request_to_the_request_handler($queue, $handler)
    {
        $modifyDn = new ModifyDnRequest('cn=foo,dc=bar', 'cn=bar', true);
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar')),
            new LdapMessageRequest(2, $modifyDn),
            null
        );

        $handler->modifyDn(Argument::any(), $modifyDn)->shouldBeCalled();
        $this->setRequestHandler($handler);
        $this->handle();
    }

    function it_should_send_an_extended_request_to_the_request_handler($queue, $handler)
    {
        $ext = new ExtendedRequest('foo', 'bar');
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar')),
            new LdapMessageRequest(2, $ext),
            null
        );

        $handler->extended(Argument::any(), $ext)->shouldBeCalled();
        $this->setRequestHandler($handler);
        $this->handle();
    }


    function it_should_send_a_compare_request_to_the_request_handler($queue, $handler)
    {
        $compare = new CompareRequest('cn=foo,dc=bar', Filters::equal('foo', 'bar'));
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar')),
            new LdapMessageRequest(2, $compare),
            null
        );

        $handler->compare(Argument::any(), $compare)->shouldBeCalled()->willReturn(true);
        $this->setRequestHandler($handler);
        $this->handle();
    }

    function it_should_send_a_search_request_to_the_request_handler($queue, $handler, $socket)
    {
        $search = (new SearchRequest(Filters::equal('foo', 'bar')))->base('dc=foo,dc=bar');
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar')),
            new LdapMessageRequest(2, $search),
            null
        );

        $encoder = new LdapEncoder();
        $entries = new Entries(Entry::create('dc=foo,dc=bar', ['cn' => 'foo']), Entry::create('dc=bar,dc=foo', ['cn' => 'bar']));
        $resultEntry = $encoder->encode((new LdapMessageResponse(2, new SearchResultEntry(Entry::create('dc=foo,dc=bar', ['cn' => 'foo']))))->toAsn1());
        $resultEntry .= $encoder->encode((new LdapMessageResponse(2, new SearchResultEntry(Entry::create('dc=bar,dc=foo', ['cn' => 'bar']))))->toAsn1());

        $handler->search(Argument::any(), $search)->shouldBeCalled()->willReturn($entries);
        $socket->write($resultEntry)->shouldBeCalled();
        $socket->write($encoder->encode((new LdapMessageResponse(2, new SearchResultDone(0)))->toAsn1()))->shouldBeCalled();
        $this->setRequestHandler($handler);
        $this->handle();
    }

    function it_should_send_a_bind_request_to_the_request_handler($queue, $handler)
    {
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new SimpleBindRequest('foo@bar', 'bar')),
            null
        );

        $handler->bind('foo@bar', 'bar')->shouldBeCalled()->willReturn(true);
        $this->setRequestHandler($handler);
        $this->handle();
    }

    function it_should_send_a_protocol_error_back_on_a_bind_request_with_an_unsupported_version($queue, $handler, $socket)
    {
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new SimpleBindRequest('foo@bar', 'bar', 4)),
            null
        );

        $encoder = new LdapEncoder();
        $socket->write($encoder->encode((new LdapMessageResponse(1, new BindResponse(new LdapResult(
            ResultCode::PROTOCOL_ERROR,
            '',
            'Only LDAP version 3 is supported.'
        ))))->toAsn1()))->shouldBeCalled();
        $handler->bind('foo@bar', 'bar')->shouldNotBeCalled();
        $this->setRequestHandler($handler);
        $this->handle();
    }

    function it_should_handle_operation_errors_thrown_from_the_request_handlers($queue, $handler, $socket)
    {
        $modify = new ModifyRequest('cn=foo,dc=bar', Change::add('foo', 'bar'));
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar')),
            new LdapMessageRequest(2, $modify),
            null
        );

        $encoder = new LdapEncoder();
        $handler->modify(Argument::any(), $modify)->shouldBeCalled()->willThrow(new OperationException('Foo.', ResultCode::CONFIDENTIALITY_REQUIRED));
        $socket->write($encoder->encode((new LdapMessageResponse(2, new ModifyResponse(ResultCode::CONFIDENTIALITY_REQUIRED, 'cn=foo,dc=bar', 'Foo.')))->toAsn1()))->shouldBeCalled();
        $this->setRequestHandler($handler);
        $this->handle();
    }

    function it_should_send_back_a_RootDSE($queue, $handler, $socket)
    {
        $search = (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope();
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, $search),
            null
        );

        $encoder = new LdapEncoder();
        $socket->write($encoder->encode((new LdapMessageResponse(1, new SearchResultEntry(Entry::create('', [
            'namingContexts' => 'dc=FreeDSx,dc=local',
            'supportedExtension' => [
                ExtendedRequest::OID_WHOAMI,
            ],
            'supportedLDAPVersion' => ['3'],
            'vendorName' => 'FreeDSx',
        ]))))->toAsn1()))->shouldBeCalled();
        $handler->search(Argument::any(), Argument::any())->shouldNotBeCalled();

        $this->setRequestHandler($handler);
        $this->handle();
    }

    function it_should_only_return_specific_attributes_from_the_RootDSE_if_requested($queue, $handler, $socket)
    {
        $search = (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope()->setAttributesOnly(true);
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, $search),
            null
        );

        $encoder = new LdapEncoder();
        $socket->write($encoder->encode((new LdapMessageResponse(1, new SearchResultEntry(Entry::create('', [
            'namingContexts' => [],
            'supportedExtension' => [],
            'supportedLDAPVersion' => [],
            'vendorName' => [],
        ]))))->toAsn1()))->shouldBeCalled();
        $handler->search(Argument::any(), Argument::any())->shouldNotBeCalled();

        $this->setRequestHandler($handler);
        $this->handle();
    }

    function it_should_only_return_attributes_from_the_RootDSE_if_requested($queue, $handler, $socket)
    {
        $search = (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope()->setAttributes('namingcontexts');
        $queue->getMessage()->willReturn(
            new LdapMessageRequest(1, $search),
            null
        );

        $encoder = new LdapEncoder();
        $socket->write($encoder->encode((new LdapMessageResponse(1, new SearchResultEntry(Entry::create('', ['namingContexts' => 'dc=FreeDSx,dc=local',]))))->toAsn1()))->shouldBeCalled();
        $handler->search(Argument::any(), Argument::any())->shouldNotBeCalled();

        $this->setRequestHandler($handler);
        $this->handle();
    }

    function it_should_not_allow_a_request_handler_as_an_object($queue, $socket)
    {
        $this->shouldThrow(RuntimeException::class)->during('__construct', [$socket, ['request_handler' => new GenericRequestHandler()], $queue]);
    }

    function it_should_only_allow_a_request_handler_implementing_request_handler_interface($queue, $socket)
    {
        $this->shouldThrow(RuntimeException::class)->during('__construct', [$socket, ['request_handler' => new Entry('foo')], $queue]);
    }

    function it_should_allow_a_request_handler_as_a_string_implementing_request_handler_interface($socket, $queue)
    {
        $this->shouldNotThrow(RuntimeException::class)->during('__construct', [$socket, ['request_handler' => ProxyRequestHandler::class], $queue]);
    }


}
