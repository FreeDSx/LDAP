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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Bind;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\SaslNegotiationAbortedException;
use FreeDSx\Ldap\Exception\ResponseAlreadySentException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdResolver;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderFactory;
use FreeDSx\Ldap\Protocol\Bind\Sasl\SaslExchange;
use FreeDSx\Ldap\Protocol\Bind\SaslBind;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\SaslIdentity;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Sasl\Mechanism\MechanismName;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class SaslBindTest extends TestCase
{
    private SaslBind $subject;

    private ServerQueue&MockObject $mockQueue;

    private PasswordAuthenticatableInterface&MockObject $mockAuthenticator;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockAuthenticator = $this->createMock(PasswordAuthenticatableInterface::class);

        $this->subject = new SaslBind(
            queue: $this->mockQueue,
            exchange: new SaslExchange(
                $this->mockQueue,
                new ResponseFactory(),
                new MechanismOptionsBuilderFactory($this->mockAuthenticator),
                $this->authzIdResolver(),
            ),
            mechanisms: [ServerOptions::SASL_PLAIN],
        );
    }

    public function test_it_supports_sasl_bind_requests(): void
    {
        self::assertTrue($this->subject->supports(new LdapMessageRequest(
            1,
            new SaslBindRequest('PLAIN'),
        )));
    }

    public function test_it_does_not_support_other_bind_request_types(): void
    {
        self::assertFalse($this->subject->supports(new LdapMessageRequest(
            1,
            new AnonBindRequest(),
        )));
        self::assertFalse($this->subject->supports(new LdapMessageRequest(
            1,
            new SimpleBindRequest('foo', 'bar'),
        )));
    }

    public function test_it_validates_the_ldap_version(): void
    {
        $this->mockQueue
            ->expects(self::never())
            ->method('sendMessage');

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $this->subject->bind(new LdapMessageRequest(
            1,
            (new SaslBindRequest('PLAIN'))->setVersion(2),
        ));
    }

    public function test_it_throws_for_an_unsupported_mechanism(): void
    {
        $this->mockQueue
            ->expects(self::never())
            ->method('sendMessage');

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::AUTH_METHOD_UNSUPPORTED);

        $this->subject->bind(new LdapMessageRequest(
            1,
            new SaslBindRequest('GSSAPI'),
        ));
    }

    public function test_it_can_authenticate_with_plain(): void
    {
        // PLAIN credential format: "authzid\x00authcid\x00passwd", with an explicit authzid naming the same identity.
        $credentials = "cn=user,dc=foo,dc=bar\x00cn=user,dc=foo,dc=bar\x0012345";
        $identity = new SaslIdentity('12345', new Dn('cn=user,dc=foo,dc=bar'));

        $this->mockAuthenticator
            ->expects(self::once())
            ->method('getSaslIdentity')
            ->with('cn=user,dc=foo,dc=bar', MechanismName::PLAIN)
            ->willReturn($identity);

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage');

        $token = $this->subject->bind(new LdapMessageRequest(
            1,
            new SaslBindRequest('PLAIN', $credentials),
        ));

        self::assertInstanceOf(
            BindToken::class,
            $token,
        );
        self::assertSame(
            'cn=user,dc=foo,dc=bar',
            $token->getUsername(),
        );
    }

    public function test_it_honors_a_proxy_authz_id_when_the_grant_is_present(): void
    {
        // PLAIN authzid (dn:) distinct from the authenticated identity: a proxy request.
        $credentials = "dn:cn=alice,dc=foo,dc=bar\x00cn=admin,dc=foo,dc=bar\x0012345";
        $identity = new SaslIdentity('12345', new Dn('cn=admin,dc=foo,dc=bar'));

        $this->mockAuthenticator
            ->expects(self::once())
            ->method('getSaslIdentity')
            ->with('cn=admin,dc=foo,dc=bar', MechanismName::PLAIN)
            ->willReturn($identity);

        $accessControl = $this->createMock(AccessControlInterface::class);
        $accessControl->method('mayUseControl')->willReturn(true);
        $backend = $this->createMock(LdapBackendInterface::class);
        $backend->method('get')->willReturn(new Entry(new Dn('cn=alice,dc=foo,dc=bar')));

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage');

        $token = $this->subjectWith($this->resolverWith(
            $accessControl,
            $backend,
        ))->bind(new LdapMessageRequest(
            1,
            new SaslBindRequest('PLAIN', $credentials),
        ));

        self::assertInstanceOf(
            BindToken::class,
            $token,
        );
        self::assertSame(
            'cn=alice,dc=foo,dc=bar',
            $token->getResolvedDn()->toString(),
        );
        self::assertSame(
            'cn=admin,dc=foo,dc=bar',
            $token->getAuthorizingDn()?->toString(),
        );
    }

    public function test_it_denies_a_proxy_authz_id_without_the_grant(): void
    {
        $credentials = "dn:cn=alice,dc=foo,dc=bar\x00cn=admin,dc=foo,dc=bar\x0012345";
        $identity = new SaslIdentity('12345', new Dn('cn=admin,dc=foo,dc=bar'));

        $this->mockAuthenticator
            ->method('getSaslIdentity')
            ->willReturn($identity);

        $accessControl = $this->createMock(AccessControlInterface::class);
        $accessControl->method('mayUseControl')->willReturn(false);

        // The deny occurs after the exchange authenticated; the dispatcher sends the error, not us.
        $this->mockQueue
            ->expects(self::never())
            ->method('sendMessage');

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::AUTHORIZATION_DENIED);

        $this->subjectWith($this->resolverWith(
            $accessControl,
            $this->createMock(LdapBackendInterface::class),
        ))->bind(new LdapMessageRequest(
            1,
            new SaslBindRequest('PLAIN', $credentials),
        ));
    }

    public function test_it_denies_a_malformed_authz_id(): void
    {
        // 'bogus' is neither empty, a dn:, nor a u: form, and differs from the authcid.
        $credentials = "bogus\x00cn=admin,dc=foo,dc=bar\x0012345";
        $identity = new SaslIdentity('12345', new Dn('cn=admin,dc=foo,dc=bar'));

        $this->mockAuthenticator
            ->method('getSaslIdentity')
            ->willReturn($identity);

        $this->mockQueue
            ->expects(self::never())
            ->method('sendMessage');

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::AUTHORIZATION_DENIED);

        $this->subject->bind(new LdapMessageRequest(
            1,
            new SaslBindRequest('PLAIN', $credentials),
        ));
    }

    public function test_it_throws_invalid_credentials_when_plain_authentication_fails(): void
    {
        $credentials = "user\x00cn=user,dc=foo,dc=bar\x00wrong";

        // Returning null means identity not found → validate() returns false → INVALID_CREDENTIALS.
        $this->mockAuthenticator
            ->expects(self::once())
            ->method('getSaslIdentity')
            ->with('cn=user,dc=foo,dc=bar', MechanismName::PLAIN)
            ->willReturn(null);

        // The failure response is sent here, so the dispatcher must be told not to send a second one.
        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage');

        self::expectException(ResponseAlreadySentException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->subject->bind(new LdapMessageRequest(
            1,
            new SaslBindRequest('PLAIN', $credentials),
        ));
    }

    public function test_challenge_mechanism_sends_invalid_credentials_on_authentication_failure(): void
    {
        $subject = new SaslBind(
            queue: $this->mockQueue,
            exchange: new SaslExchange(
                $this->mockQueue,
                new ResponseFactory(),
                new MechanismOptionsBuilderFactory($this->mockAuthenticator),
                $this->authzIdResolver(),
            ),
            mechanisms: [ServerOptions::SASL_CRAM_MD5],
        );

        // Return a real identity so the HMAC callable runs; the client digest is wrong so
        // the challenge will set isAuthenticated=false and isComplete=true.
        $identity = new SaslIdentity('correctpassword', new Dn('cn=user,dc=foo,dc=bar'));

        $this->mockAuthenticator
            ->method('getSaslIdentity')
            ->willReturn($identity);

        // First sendMessage: SASL_BIND_IN_PROGRESS (the server challenge).
        // Second sendMessage: INVALID_CREDENTIALS (the failure response).
        $this->mockQueue
            ->expects(self::exactly(2))
            ->method('sendMessage');

        // Client responds with a syntactically valid CRAM-MD5 response but the wrong HMAC.
        // CRAM-MD5 response format: "<username> <32-char-hex-md5>"
        $this->mockQueue
            ->expects(self::once())
            ->method('getMessage')
            ->willReturn(new LdapMessageRequest(
                2,
                new SaslBindRequest(
                    'CRAM-MD5',
                    'cn=user,dc=foo,dc=bar aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                ),
            ));

        self::expectException(ResponseAlreadySentException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $subject->bind(new LdapMessageRequest(
            1,
            new SaslBindRequest('CRAM-MD5'),
        ));
    }

    public function test_it_throws_runtime_exception_when_bind_is_called_with_a_non_sasl_request(): void
    {
        $this->mockQueue->expects(self::never())->method('sendMessage');

        self::expectException(RuntimeException::class);

        $this->subject->bind(new LdapMessageRequest(
            1,
            new SimpleBindRequest('cn=user', 'pass'),
        ));
    }

    /**
     * RFC 4511 4.2.1 names an AuthenticationChoice other than sasl as a way to abandon the negotiation.
     */
    public function test_a_simple_bind_during_the_exchange_aborts_the_negotiation(): void
    {
        $subject = new SaslBind(
            queue: $this->mockQueue,
            exchange: new SaslExchange(
                $this->mockQueue,
                new ResponseFactory(),
                new MechanismOptionsBuilderFactory($this->mockAuthenticator),
                $this->authzIdResolver(),
            ),
            mechanisms: [ServerOptions::SASL_CRAM_MD5],
        );

        // Only the challenge; the aborting bind is answered where it is dispatched, not refused here.
        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage');

        $this->mockQueue
            ->expects(self::once())
            ->method('getMessage')
            ->willReturn(new LdapMessageRequest(
                2,
                new SimpleBindRequest('foo', 'bar'),
            ));

        self::expectException(SaslNegotiationAbortedException::class);

        $subject->bind(new LdapMessageRequest(
            1,
            new SaslBindRequest('CRAM-MD5'),
        ));
    }

    private function authzIdResolver(): AuthzIdResolver
    {
        return $this->resolverWith(
            $this->createMock(AccessControlInterface::class),
            $this->createMock(LdapBackendInterface::class),
        );
    }

    private function resolverWith(
        AccessControlInterface $accessControl,
        LdapBackendInterface $backend,
    ): AuthzIdResolver {
        return new AuthzIdResolver(
            $accessControl,
            $backend,
            $this->createMock(BindNameResolverInterface::class),
            new EventLogger(null),
        );
    }

    private function subjectWith(AuthzIdResolver $resolver): SaslBind
    {
        return new SaslBind(
            queue: $this->mockQueue,
            exchange: new SaslExchange(
                $this->mockQueue,
                new ResponseFactory(),
                new MechanismOptionsBuilderFactory($this->mockAuthenticator),
                $resolver,
            ),
            mechanisms: [ServerOptions::SASL_PLAIN],
        );
    }
}
