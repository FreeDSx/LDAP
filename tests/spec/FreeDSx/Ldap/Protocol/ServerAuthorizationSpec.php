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

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Token\AnonToken;
use PhpSpec\ObjectBehavior;

class ServerAuthorizationSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ServerAuthorization::class);
    }

    function it_should_have_an_anonymous_token_by_default()
    {
        $this->getToken()->shouldBeAnInstanceOf(AnonToken::class);
    }

    function it_should_set_the_token()
    {
        $token = new AnonToken('foo');

        $this->setToken($token);
        $this->getToken()->shouldBeEqualTo($token);
    }

    function it_should_not_require_authentication_for_a_start_tls_request()
    {
        $this->isAuthenticationRequired(Operations::extended(ExtendedRequest::OID_START_TLS))->shouldBeEqualTo(false);
    }

    function it_should_not_require_authentication_for_a_whoami_request()
    {
        $this->isAuthenticationRequired(Operations::extended(ExtendedRequest::OID_WHOAMI))->shouldBeEqualTo(false);
    }

    function it_should_not_require_authentication_for_a_bind_request()
    {
        $this->isAuthenticationRequired(Operations::bind('foo', 'bar'))->shouldBeEqualTo(false);
    }

    function it_should_not_require_authentication_for_an_unbind_request()
    {
        $this->isAuthenticationRequired(Operations::unbind())->shouldBeEqualTo(false);
    }

    function it_should_not_require_authentication_for_a_rootdse_request()
    {
        $this->isAuthenticationRequired(Operations::read(''))->shouldBeEqualTo(false);
    }

    function it_should_require_authentication_for_all_other_operations()
    {
        $this->isAuthenticationRequired(Operations::read('cn=bar'))->shouldBeEqualTo(true);
        $this->isAuthenticationRequired(Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'))->shouldBeEqualTo(true);
        $this->isAuthenticationRequired(Operations::search(new EqualityFilter('foo', 'bar'), 'cn=foo'))->shouldBeEqualTo(true);
        $this->isAuthenticationRequired(Operations::add(Entry::fromArray('', [])))->shouldBeEqualTo(true);
        $this->isAuthenticationRequired(Operations::delete('cn=foo'))->shouldBeEqualTo(true);
        $this->isAuthenticationRequired(Operations::rename('cn=foo', 'cn=foo'))->shouldBeEqualTo(true);
        $this->isAuthenticationRequired(Operations::abandon(1))->shouldBeEqualTo(true);
        $this->isAuthenticationRequired(Operations::passwordModify('', '', ''))->shouldBeEqualTo(true);
        $this->isAuthenticationRequired(Operations::modify('cn=foo', Change::reset('foo')))->shouldBeEqualTo(true);
        $this->isAuthenticationRequired(Operations::compare('cn=foo', 'foo', 'bar'))->shouldBeEqualTo(true);
    }

    function it_should_not_require_authentication_if_it_has_been_explicitly_disabled()
    {
        $this->beConstructedWith(null, ['require_authentication' => false]);

        $this->isAuthenticationRequired(Operations::read('cn=bar'))->shouldBeEqualTo(false);
        $this->isAuthenticationRequired(Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'))->shouldBeEqualTo(false);
        $this->isAuthenticationRequired(Operations::search(new EqualityFilter('foo', 'bar'), 'cn=foo'))->shouldBeEqualTo(false);
        $this->isAuthenticationRequired(Operations::add(Entry::fromArray('', [])))->shouldBeEqualTo(false);
        $this->isAuthenticationRequired(Operations::delete('cn=foo'))->shouldBeEqualTo(false);
        $this->isAuthenticationRequired(Operations::rename('cn=foo', 'cn=foo'))->shouldBeEqualTo(false);
        $this->isAuthenticationRequired(Operations::abandon(1))->shouldBeEqualTo(false);
        $this->isAuthenticationRequired(Operations::passwordModify('', '', ''))->shouldBeEqualTo(false);
        $this->isAuthenticationRequired(Operations::modify('cn=foo', Change::reset('foo')))->shouldBeEqualTo(false);
        $this->isAuthenticationRequired(Operations::compare('cn=foo', 'foo', 'bar'))->shouldBeEqualTo(false);
    }

    function it_should_not_allow_anonymous_authentication_by_default()
    {
        $this->isAuthenticationTypeSupported(Operations::bindAnonymously())->shouldBeEqualTo(false);
    }

    function it_should_respect_the_option_for_whether_anon_binds_are_allowed()
    {
        $this->beConstructedWith(null, ['allow_anonymous' => true]);

        $this->isAuthenticationTypeSupported(Operations::bindAnonymously())->shouldBeEqualTo(true);
    }

    function it_should_allow_simple_bind_types()
    {
        $this->isAuthenticationTypeSupported(Operations::bind('foo', 'bar'))->shouldBeEqualTo(true);
    }

    function it_should_tell_if_a_request_is_an_authentication_type()
    {
        $this->isAuthenticationRequest(Operations::bind('foo', 'bar'))->shouldBeEqualTo(true);
        $this->isAuthenticationRequest(Operations::bindAnonymously())->shouldBeEqualTo(true);
    }

    function it_should_tell_if_a_request_is_not_an_authentication_type()
    {
        $this->isAuthenticationRequest(Operations::read('cn=bar'))->shouldBeEqualTo(false);
        $this->isAuthenticationRequest(Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'))->shouldBeEqualTo(false);
        $this->isAuthenticationRequest(Operations::search(new EqualityFilter('foo', 'bar'), 'cn=foo'))->shouldBeEqualTo(false);
        $this->isAuthenticationRequest(Operations::add(Entry::fromArray('', [])))->shouldBeEqualTo(false);
        $this->isAuthenticationRequest(Operations::delete('cn=foo'))->shouldBeEqualTo(false);
        $this->isAuthenticationRequest(Operations::rename('cn=foo', 'cn=foo'))->shouldBeEqualTo(false);
        $this->isAuthenticationRequest(Operations::abandon(1))->shouldBeEqualTo(false);
        $this->isAuthenticationRequest(Operations::passwordModify('', '', ''))->shouldBeEqualTo(false);
        $this->isAuthenticationRequest(Operations::modify('cn=foo', Change::reset('foo')))->shouldBeEqualTo(false);
        $this->isAuthenticationRequest(Operations::compare('cn=foo', 'foo', 'bar'))->shouldBeEqualTo(false);
    }
}
