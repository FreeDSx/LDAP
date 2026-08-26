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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Authorization;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ProxyAuthorizationControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Protocol\Authorization\DispatchAuthorizer;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdResolver;
use FreeDSx\Ldap\Protocol\Authorization\ProxiedAuthorizationResolver;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordResetGate;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class DispatchAuthorizerTest extends TestCase
{
    private const BOUND_DN = 'cn=admin,dc=example,dc=com';

    private const PROXIED_DN = 'cn=alice,dc=example,dc=com';

    private ServerAuthorization&MockObject $authorizer;

    private ReadBackendInterface&MockObject $backend;

    private AccessControlInterface&MockObject $accessControl;

    private DispatchAuthorizer $subject;

    protected function setUp(): void
    {
        $this->authorizer = $this->createMock(ServerAuthorization::class);
        $this->backend = $this->createMock(ReadBackendInterface::class);
        $this->accessControl = $this->createMock(AccessControlInterface::class);
        $this->accessControl
            ->method('mayUseControl')
            ->willReturn(true);
        $this->subject = new DispatchAuthorizer(
            $this->authorizer,
            new PasswordResetGate(),
            new ProxiedAuthorizationResolver(
                new AuthzIdResolver(
                    $this->accessControl,
                    $this->backend,
                    $this->createMock(BindNameResolverInterface::class),
                    new EventLogger(null),
                ),
            ),
        );
    }

    public function test_it_requires_authentication_when_unauthenticated_and_required(): void
    {
        $this->authorizer
            ->method('isAuthenticated')
            ->willReturn(false);
        $this->authorizer
            ->method('isAuthenticationRequired')
            ->willReturn(true);

        $authorization = $this->subject->authorize($this->message());

        self::assertTrue($authorization->requiresAuthentication());
    }

    public function test_it_requires_a_password_change_for_a_pwd_reset_identity(): void
    {
        $token = $this->boundToken();
        $token->markMustChangePassword();
        $this->authorizer
            ->method('isAuthenticated')
            ->willReturn(true);
        $this->authorizer
            ->method('getToken')
            ->willReturn($token);

        $authorization = $this->subject->authorize($this->message());

        self::assertTrue($authorization->requiresPasswordChange());
    }

    public function test_it_lets_a_pwd_reset_identity_proceed_with_a_password_change(): void
    {
        $token = $this->boundToken();
        $token->markMustChangePassword();
        $this->authorizer
            ->method('isAuthenticated')
            ->willReturn(true);
        $this->authorizer
            ->method('getToken')
            ->willReturn($token);

        $authorization = $this->subject->authorize(new LdapMessageRequest(
            1,
            new ExtendedRequest(ExtendedRequest::OID_PWD_MODIFY),
        ));

        self::assertFalse($authorization->requiresPasswordChange());
        self::assertSame(
            $token,
            $authorization->token(),
        );
    }

    public function test_it_proceeds_under_the_bound_token_without_a_proxy_control(): void
    {
        $token = $this->boundToken();
        $this->authorizer
            ->method('isAuthenticated')
            ->willReturn(true);
        $this->authorizer
            ->method('getToken')
            ->willReturn($token);

        $authorization = $this->subject->authorize($this->message());

        self::assertSame(
            $token,
            $authorization->token(),
        );
    }

    public function test_it_proceeds_under_the_proxied_identity_when_a_proxy_control_is_present(): void
    {
        $this->authorizer
            ->method('isAuthenticated')
            ->willReturn(true);
        $this->authorizer
            ->method('getToken')
            ->willReturn($this->boundToken());
        $this->backend
            ->method('get')
            ->willReturn(new Entry(self::PROXIED_DN));

        $authorization = $this->subject->authorize($this->message(
            new ProxyAuthorizationControl(AuthzId::fromString('dn:' . self::PROXIED_DN)),
        ));

        $effective = $authorization->token();
        self::assertInstanceOf(
            AuthenticatedTokenInterface::class,
            $effective,
        );
        self::assertSame(
            self::PROXIED_DN,
            $effective->getResolvedDn()->toString(),
        );
    }

    public function test_it_propagates_a_proxy_authorization_denial(): void
    {
        $this->authorizer
            ->method('isAuthenticated')
            ->willReturn(true);
        $this->authorizer
            ->method('getToken')
            ->willReturn($this->boundToken());
        $this->backend
            ->method('get')
            ->willReturn(new Entry(self::PROXIED_DN));
        $this->accessControl
            ->method('authorizeControl')
            ->willThrowException(new OperationException(
                'Access denied.',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::AUTHORIZATION_DENIED);

        $this->subject->authorize($this->message(
            new ProxyAuthorizationControl(AuthzId::fromString('dn:' . self::PROXIED_DN)),
        ));
    }

    private function boundToken(): BindToken
    {
        return BindToken::fromDn(
            self::BOUND_DN,
        );
    }

    private function message(Control ...$controls): LdapMessageRequest
    {
        return new LdapMessageRequest(
            1,
            new DeleteRequest(self::PROXIED_DN),
            ...$controls,
        );
    }
}
