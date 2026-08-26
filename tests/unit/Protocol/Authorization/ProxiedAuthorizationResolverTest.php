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

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\ProxyAuthorizationControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdResolver;
use FreeDSx\Ldap\Protocol\Authorization\ProxiedAuthorizationResolver;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

final class ProxiedAuthorizationResolverTest extends TestCase
{
    private const ADMIN_DN = 'cn=admin,dc=example,dc=com';

    private const PROXIED_DN = 'cn=alice,dc=example,dc=com';

    private AccessControlInterface&MockObject $accessControl;

    private ReadBackendInterface&MockObject $backend;

    private BindNameResolverInterface&MockObject $identityResolver;

    private RecordingLogger $recordingLogger;

    private ProxiedAuthorizationResolver $subject;

    private BindToken $boundToken;

    protected function setUp(): void
    {
        $this->accessControl = $this->createMock(AccessControlInterface::class);
        $this->backend = $this->createMock(ReadBackendInterface::class);
        $this->identityResolver = $this->createMock(BindNameResolverInterface::class);
        $this->recordingLogger = new RecordingLogger();
        $this->subject = new ProxiedAuthorizationResolver(
            new AuthzIdResolver(
                $this->accessControl,
                $this->backend,
                $this->identityResolver,
                new EventLogger(
                    $this->recordingLogger,
                    EventLogPolicy::all(),
                ),
            ),
        );
        $this->boundToken = BindToken::fromDn(
            self::ADMIN_DN,
        );
    }

    public function test_it_returns_the_bound_token_when_no_proxy_control_is_present(): void
    {
        $result = $this->subject->resolve(
            $this->eligibleRequest(),
            new ControlBag(),
            $this->boundToken,
        );

        self::assertSame(
            $this->boundToken,
            $result,
        );
    }

    public function test_it_resolves_a_dn_authz_id_to_the_proxied_identity(): void
    {
        $this->grantProxyCapability();
        $this->backend
            ->method('get')
            ->willReturn(new Entry(self::PROXIED_DN));

        $result = $this->subject->resolve(
            $this->eligibleRequest(),
            new ControlBag(new ProxyAuthorizationControl(AuthzId::fromString('dn:' . self::PROXIED_DN))),
            $this->boundToken,
        );

        self::assertInstanceOf(
            AuthenticatedTokenInterface::class,
            $result,
        );
        self::assertSame(
            self::PROXIED_DN,
            $result->getResolvedDn()->toString(),
        );
        self::assertSame(
            self::ADMIN_DN,
            $result->getAuthorizingDn()?->toString(),
        );
    }

    public function test_it_resolves_a_userid_authz_id_via_the_identity_resolver(): void
    {
        $this->grantProxyCapability();
        $this->identityResolver
            ->method('resolve')
            ->willReturn(new Entry(self::PROXIED_DN));

        $result = $this->subject->resolve(
            $this->eligibleRequest(),
            new ControlBag(new ProxyAuthorizationControl(AuthzId::fromString('u:alice'))),
            $this->boundToken,
        );

        self::assertInstanceOf(
            AuthenticatedTokenInterface::class,
            $result,
        );
        self::assertSame(
            self::PROXIED_DN,
            $result->getResolvedDn()->toString(),
        );
    }

    public function test_it_returns_an_anonymous_identity_for_an_empty_authz_id(): void
    {
        $this->grantProxyCapability();

        $result = $this->subject->resolve(
            $this->eligibleRequest(),
            new ControlBag(new ProxyAuthorizationControl(AuthzId::anonymous())),
            $this->boundToken,
        );

        self::assertNotInstanceOf(
            AuthenticatedTokenInterface::class,
            $result,
        );
        self::assertSame(
            self::ADMIN_DN,
            $result->getAuthorizingDn()?->toString(),
        );
    }

    public function test_it_denies_without_resolving_when_the_subject_has_no_proxy_capability(): void
    {
        $this->accessControl
            ->method('mayUseControl')
            ->willReturn(false);
        $this->backend
            ->expects(self::never())
            ->method('get');
        $this->identityResolver
            ->expects(self::never())
            ->method('resolve');

        $this->assertDeniesWith(
            new ProxyAuthorizationControl(AuthzId::fromString('dn:' . self::PROXIED_DN)),
            'dn:' . self::PROXIED_DN,
        );
    }

    public function test_it_denies_when_the_bound_identity_lacks_proxy_permission_for_the_target(): void
    {
        $this->grantProxyCapability();
        $this->backend
            ->method('get')
            ->willReturn(new Entry(self::PROXIED_DN));
        $this->accessControl
            ->method('authorizeControl')
            ->willThrowException(new OperationException(
                'Access denied.',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            ));

        $this->assertDeniesWith(
            new ProxyAuthorizationControl(AuthzId::fromString('dn:' . self::PROXIED_DN)),
            'dn:' . self::PROXIED_DN,
        );
    }

    public function test_it_denies_when_the_authz_id_cannot_be_resolved(): void
    {
        $this->grantProxyCapability();
        $this->backend
            ->method('get')
            ->willReturn(null);

        $this->assertDeniesWith(
            new ProxyAuthorizationControl(AuthzId::fromString('dn:' . self::PROXIED_DN)),
            'dn:' . self::PROXIED_DN,
        );
    }

    public function test_it_denies_a_malformed_dn_authz_id_without_disconnecting(): void
    {
        $this->grantProxyCapability();
        $this->backend
            ->method('get')
            ->willThrowException(new InvalidArgumentException('The DN value is not valid.'));

        $this->assertDeniesWith(
            new ProxyAuthorizationControl(AuthzId::fromString('dn:not a dn')),
            'dn:not a dn',
        );
    }

    public function test_it_denies_an_unknown_authz_id_form(): void
    {
        $this->grantProxyCapability();

        // A malformed authzId form can only originate from the wire, so build it via fromAsn1.
        $this->assertDeniesWith(
            ProxyAuthorizationControl::fromAsn1(Asn1::sequence(
                Asn1::octetString(Control::OID_PROXY_AUTHORIZATION),
                Asn1::boolean(true),
                Asn1::octetString('mail:alice@example.com'),
            )),
            'mail:alice@example.com',
        );
    }

    public function test_it_denies_when_the_bound_identity_is_not_authenticated(): void
    {
        try {
            $this->subject->resolve(
                $this->eligibleRequest(),
                new ControlBag(new ProxyAuthorizationControl(AuthzId::fromString('dn:' . self::PROXIED_DN))),
                new AnonToken(),
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::AUTHORIZATION_DENIED,
                $e->getCode(),
            );
        }

        $this->assertDenialLogged('dn:' . self::PROXIED_DN);
    }

    #[DataProvider('ineligibleExtendedOidProvider')]
    public function test_it_rejects_the_control_on_an_ineligible_operation(string $extendedOid): void
    {
        try {
            $this->subject->resolve(
                new ExtendedRequest($extendedOid),
                new ControlBag(new ProxyAuthorizationControl(AuthzId::fromString('dn:' . self::PROXIED_DN))),
                $this->boundToken,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
                $e->getCode(),
            );
        }

        self::assertCount(
            0,
            $this->recordingLogger->records,
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function ineligibleExtendedOidProvider(): array
    {
        return [
            'StartTLS' => [ExtendedRequest::OID_START_TLS],
            'PasswordModify' => [ExtendedRequest::OID_PWD_MODIFY],
        ];
    }

    public function test_it_rejects_a_non_critical_proxy_control_as_a_protocol_error(): void
    {
        try {
            $this->subject->resolve(
                $this->eligibleRequest(),
                new ControlBag(new ProxyAuthorizationControl(
                    AuthzId::fromString('dn:' . self::PROXIED_DN),
                    false,
                )),
                $this->boundToken,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::PROTOCOL_ERROR,
                $e->getCode(),
            );
        }

        self::assertCount(
            0,
            $this->recordingLogger->records,
        );
    }

    public function test_it_rejects_more_than_one_proxy_control_as_a_protocol_error(): void
    {
        try {
            $this->subject->resolve(
                $this->eligibleRequest(),
                new ControlBag(
                    new ProxyAuthorizationControl(AuthzId::fromString('dn:' . self::PROXIED_DN)),
                    new ProxyAuthorizationControl(AuthzId::fromString('u:alice')),
                ),
                $this->boundToken,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::PROTOCOL_ERROR,
                $e->getCode(),
            );
        }

        self::assertCount(
            0,
            $this->recordingLogger->records,
        );
    }

    private function grantProxyCapability(): void
    {
        $this->accessControl
            ->method('mayUseControl')
            ->willReturn(true);
    }

    private function eligibleRequest(): RequestInterface
    {
        return new DeleteRequest('cn=target,dc=example,dc=com');
    }

    private function assertDeniesWith(
        ProxyAuthorizationControl $control,
        string $expectedAuthzId,
    ): void {
        try {
            $this->subject->resolve(
                $this->eligibleRequest(),
                new ControlBag($control),
                $this->boundToken,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::AUTHORIZATION_DENIED,
                $e->getCode(),
            );
        }

        $this->assertDenialLogged($expectedAuthzId);
    }

    private function assertDenialLogged(string $expectedAuthzId): void
    {
        self::assertCount(
            1,
            $this->recordingLogger->records,
        );
        $record = $this->recordingLogger->records[0];
        self::assertSame(
            'authz.denied.proxy',
            $record['message'],
        );
        self::assertSame(
            'notice',
            $record['level'],
        );
        self::assertSame(
            ResultCode::AUTHORIZATION_DENIED,
            $record['context'][EventContext::RESULT_CODE],
        );
        self::assertSame(
            [Control::OID_PROXY_AUTHORIZATION],
            $record['context'][EventContext::CONTROL_OIDS],
        );
        self::assertSame(
            $expectedAuthzId,
            $record['context'][EventContext::AUTHZ_ID],
        );
        self::assertSame(
            'Proxied authorization denied.',
            $record['context'][EventContext::REASON],
        );
    }
}
