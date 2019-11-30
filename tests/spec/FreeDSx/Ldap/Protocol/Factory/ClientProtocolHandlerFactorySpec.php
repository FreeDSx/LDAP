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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientExtendedOperationHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientReferralHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientSaslBindHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientStartTlsHandler;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientBasicHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientSearchHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientUnbindHandler;
use PhpSpec\ObjectBehavior;

class ClientProtocolHandlerFactorySpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ClientProtocolHandlerFactory::class);
    }

    function it_should_get_a_search_response_handler(RequestInterface $request)
    {
        $this->forResponse($request, new SearchResultEntry(new Entry('')))->shouldBeAnInstanceOf(ClientSearchHandler::class);
        $this->forResponse($request, new SearchResultDone(0))->shouldBeAnInstanceOf(ClientSearchHandler::class);
    }

    function it_should_get_an_unbind_request_handler()
    {
        $this->forRequest(Operations::unbind())->shouldBeAnInstanceOf(ClientUnbindHandler::class);
    }

    function it_should_get_a_basic_request_handler()
    {
        $this->forRequest(Operations::delete('cn=foo'))->shouldBeAnInstanceOf(ClientBasicHandler::class);
        $this->forRequest(Operations::bind('foo', 'bar'))->shouldBeAnInstanceOf(ClientBasicHandler::class);
        $this->forRequest(Operations::add(new Entry('')))->shouldBeAnInstanceOf(ClientBasicHandler::class);
        $this->forRequest(Operations::modify(new Entry('')))->shouldBeAnInstanceOf(ClientBasicHandler::class);
        $this->forRequest(Operations::move('cn=foo', 'cn=bar'))->shouldBeAnInstanceOf(ClientBasicHandler::class);
        $this->forRequest(Operations::cancel(1))->shouldBeAnInstanceOf(ClientBasicHandler::class);
        $this->forRequest(Operations::whoami())->shouldBeAnInstanceOf(ClientBasicHandler::class);
    }

    function it_should_get_a_referral_handler(RequestInterface $request)
    {
        $this->forResponse($request, new DeleteResponse(ResultCode::REFERRAL))->shouldBeAnInstanceOf(
            ClientReferralHandler::class
        );
    }

    function it_should_get_an_extended_response_handler(RequestInterface $request)
    {
        $this->forResponse($request, new ExtendedResponse(new LdapResult(0)))->shouldBeAnInstanceOf(
            ClientExtendedOperationHandler::class
        );
    }

    function it_should_get_a_start_tls_handler()
    {
        $this->forResponse(new ExtendedRequest(ExtendedRequest::OID_START_TLS), new ExtendedResponse(new LdapResult(0), ExtendedRequest::OID_START_TLS))->shouldBeAnInstanceOf(
            ClientStartTlsHandler::class
        );
    }

    function it_should_get_a_basic_response_handler(RequestInterface $request)
    {
        $this->forResponse($request, new BindResponse(new LdapResult(0)))->shouldBeAnInstanceOf(
            ClientBasicHandler::class
        );
    }

    function it_should_get_a_sasl_bind_handler()
    {
        $this->forRequest(new SaslBindRequest('DIGEST-MD5'))->shouldBeAnInstanceOf(
            ClientSaslBindHandler::class
        );
    }
}
