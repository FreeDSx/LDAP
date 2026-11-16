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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Bind\Sasl;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdResolver;
use FreeDSx\Ldap\Protocol\Bind\Sasl\SaslAuthorizer;
use FreeDSx\Ldap\Schema\AttributeTypeSpelling;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class SaslAuthorizerTest extends TestCase
{
    private const ADMIN_DN = 'cn=admin,dc=foo,dc=bar';

    private const ALICE_DN = 'cn=alice,dc=foo,dc=bar';

    private AccessControlInterface&MockObject $accessControl;

    private ReadBackendInterface&MockObject $backend;

    private SaslAuthorizer $subject;

    private BindToken $authenticated;

    protected function setUp(): void
    {
        $this->accessControl = $this->createMock(AccessControlInterface::class);
        $this->backend = $this->createMock(ReadBackendInterface::class);
        $this->subject = new SaslAuthorizer(new AuthzIdResolver(
            $this->accessControl,
            $this->backend,
            $this->createMock(BindNameResolverInterface::class),
            new AttributeTypeSpelling(SchemaResource::Core->load()),
            new EventLogger(null),
        ));
        $this->authenticated = BindToken::fromSasl(
            self::ADMIN_DN,
            new Dn(self::ADMIN_DN),
        );
    }

    /**
     * @return array<string, array{?string}>
     */
    public static function selfAuthzIdProvider(): array
    {
        return [
            'absent' => [null],
            'empty' => [''],
            'the authentication identity as sent' => [self::ADMIN_DN],
            'the authentication identity by dn' => ['dn:' . self::ADMIN_DN],
        ];
    }

    #[DataProvider('selfAuthzIdProvider')]
    public function test_it_binds_as_the_authenticated_identity_when_no_other_is_asked_for(?string $authzId): void
    {
        $this->accessControl
            ->expects(self::never())
            ->method('mayUseControl');

        self::assertSame(
            $this->authenticated,
            $this->subject->authorize(
                $this->contextWith($authzId),
                $this->authenticated,
            ),
        );
    }

    public function test_it_binds_as_the_assumed_identity_with_the_proxy_grant(): void
    {
        $this->accessControl
            ->method('mayUseControl')
            ->willReturn(true);
        $this->backend
            ->method('get')
            ->willReturn(new Entry(new Dn(self::ALICE_DN)));

        $token = $this->subject->authorize(
            $this->contextWith('dn:' . self::ALICE_DN),
            $this->authenticated,
        );

        self::assertSame(
            [self::ALICE_DN, self::ADMIN_DN],
            [$token->getResolvedDn()->toString(), $token->getAuthorizingDn()?->toString()],
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function refusedAuthzIdProvider(): array
    {
        return [
            'another identity without the grant' => ['dn:' . self::ALICE_DN],
            'a malformed authzid' => ['bogus'],
        ];
    }

    #[DataProvider('refusedAuthzIdProvider')]
    public function test_a_refused_authz_id_answers_as_invalid_credentials(string $authzId): void
    {
        $this->accessControl
            ->method('mayUseControl')
            ->willReturn(false);

        try {
            $this->subject->authorize(
                $this->contextWith($authzId),
                $this->authenticated,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                [ResultCode::INVALID_CREDENTIALS, 'Invalid credentials.'],
                [$e->getCode(), $e->getMessage()],
            );
        }
    }

    private function contextWith(?string $authzId): SaslContext
    {
        return (new SaslContext())->set(
            SaslContext::AUTHZID,
            $authzId,
        );
    }
}
