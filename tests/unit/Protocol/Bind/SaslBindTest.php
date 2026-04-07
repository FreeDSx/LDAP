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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderFactory;
use FreeDSx\Ldap\Protocol\Bind\Sasl\SaslExchange;
use FreeDSx\Ldap\Protocol\Bind\SaslBind;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\ServerOptions;
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
        // PLAIN credential format: "authzid\x00authcid\x00passwd" (all three parts must be non-empty)
        $credentials = "user\x00cn=user,dc=foo,dc=bar\x0012345";

        $this->mockAuthenticator
            ->expects(self::once())
            ->method('verifyPassword')
            ->with('cn=user,dc=foo,dc=bar', '12345')
            ->willReturn(true);

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage');

        self::assertEquals(
            new BindToken('cn=user,dc=foo,dc=bar', ''),
            $this->subject->bind(new LdapMessageRequest(
                1,
                new SaslBindRequest('PLAIN', $credentials),
            )),
        );
    }

    public function test_it_throws_invalid_credentials_when_plain_authentication_fails(): void
    {
        $credentials = "user\x00cn=user,dc=foo,dc=bar\x00wrong";

        $this->mockAuthenticator
            ->expects(self::once())
            ->method('verifyPassword')
            ->with('cn=user,dc=foo,dc=bar', 'wrong')
            ->willReturn(false);

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage');

        self::expectException(OperationException::class);
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
            ),
            mechanisms: [ServerOptions::SASL_CRAM_MD5],
        );

        // Return a real password so the HMAC callable runs; the client digest is wrong so
        // the challenge will set isAuthenticated=false and isComplete=true.
        $this->mockAuthenticator
            ->method('getPassword')
            ->willReturn('correctpassword');

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
                    'cn=user,dc=foo,dc=bar aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                ),
            ));

        self::expectException(OperationException::class);
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

    public function test_it_throws_protocol_error_when_non_sasl_request_received_during_exchange(): void
    {
        $subject = new SaslBind(
            queue: $this->mockQueue,
            exchange: new SaslExchange(
                $this->mockQueue,
                new ResponseFactory(),
                new MechanismOptionsBuilderFactory($this->mockAuthenticator),
            ),
            mechanisms: [ServerOptions::SASL_CRAM_MD5],
        );

        // First sendMessage is the SASL_BIND_IN_PROGRESS challenge; second is the error response.
        $this->mockQueue
            ->expects(self::exactly(2))
            ->method('sendMessage');

        // Client sends the wrong request type during the exchange
        $this->mockQueue
            ->expects(self::once())
            ->method('getMessage')
            ->willReturn(new LdapMessageRequest(
                2,
                new SimpleBindRequest('foo', 'bar')
            ));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $subject->bind(new LdapMessageRequest(
            1,
            new SaslBindRequest('CRAM-MD5'),
        ));
    }
}
