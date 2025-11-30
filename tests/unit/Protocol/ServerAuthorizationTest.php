<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Unit\FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;

final class ServerAuthorizationTest extends TestCase
{
    private ServerAuthorization $subject;

    protected function setUp(): void
    {
        $this->subject = new ServerAuthorization(new ServerOptions());
    }

    public function test_it_should_have_an_anonymous_token_by_default(): void
    {
        self::assertInstanceOf(
            AnonToken::class,
            $this->subject->getToken(),
        );
    }

    public function test_it_should_set_the_token(): void
    {
        $token = new AnonToken('foo');

        $this->subject->setToken($token);

        self::assertEquals(
            $token,
            $this->subject->getToken(),
        );
    }

    public function test_it_should_not_require_authentication_for_a_start_tls_request(): void
    {
        self::assertFalse($this->subject->isAuthenticationRequired(
            Operations::extended(ExtendedRequest::OID_START_TLS)
        ));
    }

    public function test_it_should_not_require_authentication_for_a_whoami_request(): void
    {
        self::assertFalse($this->subject->isAuthenticationRequired(
            Operations::extended(ExtendedRequest::OID_WHOAMI)
        ));
    }

    public function test_it_should_not_require_authentication_for_a_bind_request(): void
    {
        self::assertFalse($this->subject->isAuthenticationRequired(
            Operations::bind('foo', 'bar')
        ));
    }

    public function test_it_should_not_require_authentication_for_an_unbind_request(): void
    {
        self::assertFalse($this->subject->isAuthenticationRequired(
            Operations::unbind()
        ));
    }

    public function test_it_should_not_require_authentication_for_a_rootdse_request(): void
    {
        self::assertFalse($this->subject->isAuthenticationRequired(
            Operations::read('')
        ));
    }

    /**
     * @dataProvider authExpectedRequestsDataProvider
     */
    public function test_it_should_require_authentication_for_all_other_operations(RequestInterface $request): void
    {
        self::assertTrue($this->subject->isAuthenticationRequired($request));
    }

    /**
     * @dataProvider authExpectedRequestsDataProvider
     */
    public function test_it_should_not_require_authentication_if_it_has_been_explicitly_disabled(RequestInterface $request): void
    {
        $this->subject = new ServerAuthorization(
            (new ServerOptions())
                ->setAllowAnonymous(false)
                ->setRequireAuthentication(false),
            new AnonToken()
        );

        self::assertFalse($this->subject->isAuthenticationRequired($request));
    }

    public function test_it_should_not_allow_anonymous_authentication_by_default(): void
    {
        self::assertFalse($this->subject->isAuthenticationTypeSupported(Operations::bindAnonymously()));
    }

    public function test_it_should_respect_the_option_for_whether_anon_binds_are_allowed(): void
    {
        $this->subject = new ServerAuthorization(
            (new ServerOptions())
                ->setAllowAnonymous(true),
            new AnonToken()
        );

        self::assertTrue($this->subject->isAuthenticationTypeSupported(Operations::bindAnonymously()));
    }

    public function test_it_should_allow_simple_bind_types(): void
    {
        self::assertTrue($this->subject->isAuthenticationTypeSupported(
            Operations::bind('foo', 'bar')
        ));
    }

    public function test_it_should_tell_if_a_request_is_an_authentication_type(): void
    {
        self::assertTrue($this->subject->isAuthenticationRequest(Operations::bindAnonymously()));
        self::assertTrue($this->subject->isAuthenticationRequest(Operations::bind('foo', 'bar')));
    }

    /**
     * @dataProvider authExpectedRequestsDataProvider
     */
    public function test_it_should_tell_if_a_request_is_not_an_authentication_type(RequestInterface $request): void
    {
        self::assertFalse($this->subject->isAuthenticationRequest($request));
    }

    public static function authExpectedRequestsDataProvider(): array
    {
        return [
            [Operations::read('cn=bar')],
            [Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo')],
            [Operations::search(new EqualityFilter('foo', 'bar'), 'cn=foo')],
            [Operations::add(Entry::fromArray(''))],
            [Operations::delete('cn=foo')],
            [Operations::rename('cn=foo', 'cn=foo')],
            [Operations::abandon(1)],
            [Operations::passwordModify('', '', '')],
            [Operations::modify('cn=foo', Change::reset('foo'))],
            [Operations::compare('cn=foo', 'foo', 'bar')],
        ];
    }
}
