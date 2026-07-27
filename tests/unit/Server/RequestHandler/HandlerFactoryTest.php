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

namespace Tests\Unit\FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticator;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use FreeDSx\Ldap\Server\RequestHandler\HandlerFactory;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class HandlerFactoryTest extends TestCase
{
    private WritableLdapBackendInterface&MockObject $backend;

    protected function setUp(): void
    {
        $this->backend = $this->createMock(WritableLdapBackendInterface::class);
    }

    public function test_it_returns_default_password_authenticator_when_none_is_configured(): void
    {
        $subject = new HandlerFactory(
            new ServerOptions(),
            $this->backend,
        );

        self::assertInstanceOf(
            PasswordAuthenticator::class,
            $subject->makePasswordAuthenticator(),
        );
    }

    public function test_it_prefers_explicitly_configured_password_authenticator(): void
    {
        $authenticator = $this->createMock(PasswordAuthenticatableInterface::class);

        $subject = new HandlerFactory(
            (new ServerOptions())->setPasswordAuthenticator($authenticator),
            $this->backend,
        );

        self::assertSame(
            $authenticator,
            $subject->makePasswordAuthenticator(),
        );
    }
}
