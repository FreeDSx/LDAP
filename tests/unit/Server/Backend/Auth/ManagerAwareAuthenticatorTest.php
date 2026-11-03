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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Auth;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerAwareAuthenticator;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerIdentity;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\ManagerToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class ManagerAwareAuthenticatorTest extends TestCase
{
    use ServerContainerTrait;

    private const MANAGER_DN = 'cn=manager';

    private const MANAGER_PASSWORD = '12345';

    private const MANAGER_HASH = '{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ=';

    private PasswordAuthenticatableInterface&MockObject $inner;

    private ManagerAwareAuthenticator $subject;

    protected function setUp(): void
    {
        $this->inner = $this->createMock(PasswordAuthenticatableInterface::class);
        $this->subject = new ManagerAwareAuthenticator(
            $this->inner,
            new ManagerIdentity(
                new Dn(self::MANAGER_DN),
                self::MANAGER_HASH,
            ),
            $this->fromContainer(
                PasswordHashService::class,
                options: TestServerOptions::cheaplyHashed(),
            ),
        );
    }

    public function test_manager_with_correct_password_returns_a_privileged_token(): void
    {
        $this->inner
            ->expects(self::never())
            ->method('authenticate');

        $token = $this->subject->authenticate(
            self::MANAGER_DN,
            self::MANAGER_PASSWORD,
        );

        self::assertInstanceOf(
            ManagerToken::class,
            $token,
        );
        self::assertSame(
            self::MANAGER_DN,
            $token->getResolvedDn()->toString(),
        );
    }

    public function test_manager_with_wrong_password_is_denied_without_delegating(): void
    {
        $this->inner
            ->expects(self::never())
            ->method('authenticate');
        $this->expectException(OperationException::class);

        $this->subject->authenticate(
            self::MANAGER_DN,
            'wrong',
        );
    }

    public function test_non_manager_name_delegates_to_the_inner_authenticator(): void
    {
        $token = BindToken::fromDn('cn=user,dc=foo,dc=bar');
        $this->inner
            ->expects(self::once())
            ->method('authenticate')
            ->with(
                'cn=user,dc=foo,dc=bar',
                'secret',
            )
            ->willReturn($token);

        $result = $this->subject->authenticate(
            'cn=user,dc=foo,dc=bar',
            'secret',
        );

        self::assertSame(
            $token,
            $result,
        );
    }
}
