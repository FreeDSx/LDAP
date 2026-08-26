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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdResolver;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

final class AuthzIdResolverTest extends TestCase
{
    private const ADMIN_DN = 'cn=admin,dc=example,dc=com';

    private const PROXIED_DN = 'cn=alice,dc=example,dc=com';

    private AccessControlInterface&MockObject $accessControl;

    private ReadBackendInterface&MockObject $backend;

    private BindNameResolverInterface&MockObject $identityResolver;

    private AuthzIdResolver $subject;

    private BindToken $boundToken;

    protected function setUp(): void
    {
        $this->accessControl = $this->createMock(AccessControlInterface::class);
        $this->backend = $this->createMock(ReadBackendInterface::class);
        $this->identityResolver = $this->createMock(BindNameResolverInterface::class);
        $this->subject = new AuthzIdResolver(
            $this->accessControl,
            $this->backend,
            $this->identityResolver,
            new EventLogger(
                new RecordingLogger(),
                EventLogPolicy::all(),
            ),
        );
        $this->boundToken = BindToken::fromDn(
            self::ADMIN_DN,
        );
    }

    public function test_it_resolves_a_dn_authz_id_via_the_backend(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(new Entry(new Dn(self::PROXIED_DN)));

        $entry = $this->subject->resolve(AuthzId::fromString('dn:' . self::PROXIED_DN));

        self::assertSame(
            self::PROXIED_DN,
            $entry?->getDn()->toString(),
        );
    }

    public function test_it_resolves_a_username_authz_id_via_the_identity_resolver(): void
    {
        $this->identityResolver
            ->method('resolve')
            ->willReturn(new Entry(new Dn(self::PROXIED_DN)));

        $entry = $this->subject->resolve(AuthzId::fromString('u:alice'));

        self::assertSame(
            self::PROXIED_DN,
            $entry?->getDn()->toString(),
        );
    }

    public function test_it_resolves_an_anonymous_authz_id_to_null(): void
    {
        self::assertNull($this->subject->resolve(AuthzId::fromString('')));
    }

    public function test_it_resolves_to_null_when_the_backend_throws(): void
    {
        $this->backend
            ->method('get')
            ->willThrowException(new OperationException(
                'No such object.',
                ResultCode::NO_SUCH_OBJECT,
            ));

        self::assertNull($this->subject->resolve(AuthzId::fromString('dn:' . self::PROXIED_DN)));
    }

    public function test_assume_returns_the_proxied_token_with_the_authorizing_dn(): void
    {
        $this->accessControl
            ->method('mayUseControl')
            ->willReturn(true);
        $this->backend
            ->method('get')
            ->willReturn(new Entry(new Dn(self::PROXIED_DN)));

        $token = $this->subject->assume(
            $this->boundToken,
            AuthzId::fromString('dn:' . self::PROXIED_DN),
        );

        if (!$token instanceof AuthenticatedTokenInterface) {
            self::fail('Expected an authenticated token.');
        }
        self::assertSame(
            self::PROXIED_DN,
            $token->getResolvedDn()->toString(),
        );
        self::assertSame(
            self::ADMIN_DN,
            $token->getAuthorizingDn()?->toString(),
        );
    }

    public function test_assume_returns_the_authenticated_token_when_the_authz_id_names_self_by_dn(): void
    {
        $this->accessControl
            ->expects(self::never())
            ->method('mayUseControl');
        $this->accessControl
            ->expects(self::never())
            ->method('authorizeControl');

        $token = $this->subject->assume(
            $this->boundToken,
            AuthzId::fromString('dn:' . self::ADMIN_DN),
        );

        self::assertSame(
            $this->boundToken,
            $token,
        );
    }

    public function test_assume_returns_the_authenticated_token_when_the_authz_id_names_self_by_username(): void
    {
        $boundToken = BindToken::fromUsername('alice');
        $this->accessControl
            ->expects(self::never())
            ->method('mayUseControl');
        $this->accessControl
            ->expects(self::never())
            ->method('authorizeControl');

        $token = $this->subject->assume(
            $boundToken,
            AuthzId::fromString('u:alice'),
        );

        self::assertSame(
            $boundToken,
            $token,
        );
    }

    public function test_assume_anonymous_returns_an_anonymous_token(): void
    {
        $this->accessControl
            ->method('mayUseControl')
            ->willReturn(true);

        $token = $this->subject->assume(
            $this->boundToken,
            AuthzId::fromString(''),
        );

        self::assertInstanceOf(
            AnonToken::class,
            $token,
        );
    }

    public function test_assume_is_denied_without_the_proxy_grant(): void
    {
        $this->accessControl
            ->method('mayUseControl')
            ->willReturn(false);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::AUTHORIZATION_DENIED);

        $this->subject->assume(
            $this->boundToken,
            AuthzId::fromString('dn:' . self::PROXIED_DN),
        );
    }

    public function test_assume_is_denied_when_the_target_is_not_found(): void
    {
        $this->accessControl
            ->method('mayUseControl')
            ->willReturn(true);
        $this->backend
            ->method('get')
            ->willReturn(null);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::AUTHORIZATION_DENIED);

        $this->subject->assume(
            $this->boundToken,
            AuthzId::fromString('dn:' . self::PROXIED_DN),
        );
    }

    public function test_assume_is_denied_when_the_target_is_not_authorized(): void
    {
        $this->accessControl
            ->method('mayUseControl')
            ->willReturn(true);
        $this->backend
            ->method('get')
            ->willReturn(new Entry(new Dn(self::PROXIED_DN)));
        $this->accessControl
            ->method('authorizeControl')
            ->willThrowException(new OperationException(
                'Insufficient access rights.',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::AUTHORIZATION_DENIED);

        $this->subject->assume(
            $this->boundToken,
            AuthzId::fromString('dn:' . self::PROXIED_DN),
        );
    }
}
