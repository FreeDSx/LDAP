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

use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticator;
use FreeDSx\Ldap\Server\Backend\GenericBackend;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\RequestHandler\HandlerFactory;
use FreeDSx\Ldap\Server\RequestHandler\ProxyHandler;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluator;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class HandlerFactoryTest extends TestCase
{
    private HandlerFactory $subject;

    public function test_it_should_return_a_generic_backend_when_none_is_configured(): void
    {
        $this->subject = new HandlerFactory(new ServerOptions());

        self::assertInstanceOf(
            GenericBackend::class,
            $this->subject->makeBackend()
        );
    }

    public function test_it_should_allow_a_backend_as_an_object(): void
    {
        $backend = $this->createMock(LdapBackendInterface::class);
        $this->subject = new HandlerFactory((new ServerOptions())->setBackend($backend));

        self::assertSame(
            $backend,
            $this->subject->makeBackend()
        );
    }

    public function test_it_should_return_a_default_filter_evaluator_when_none_is_configured(): void
    {
        $this->subject = new HandlerFactory(new ServerOptions());

        self::assertInstanceOf(
            FilterEvaluator::class,
            $this->subject->makeFilterEvaluator()
        );
    }

    public function test_it_should_allow_a_filter_evaluator_as_an_object(): void
    {
        $evaluator = $this->createMock(FilterEvaluatorInterface::class);
        $this->subject = new HandlerFactory((new ServerOptions())->setFilterEvaluator($evaluator));

        self::assertSame(
            $evaluator,
            $this->subject->makeFilterEvaluator()
        );
    }

    public function test_it_should_allow_a_rootdse_handler_as_an_object(): void
    {
        $rootDseHandler = new ProxyHandler(new LdapClient());
        $this->subject = new HandlerFactory((new ServerOptions())->setRootDseHandler($rootDseHandler));

        self::assertSame(
            $rootDseHandler,
            $this->subject->makeRootDseHandler()
        );
    }

    public function test_it_should_allow_a_null_rootdse_handler(): void
    {
        $this->subject = new HandlerFactory(
            (new ServerOptions())->setRootDseHandler(null)
        );

        self::assertNull($this->subject->makeRootDseHandler());
    }

    public function test_it_should_return_the_backend_as_rootdse_handler_if_it_implements_the_interface(): void
    {
        /** @var LdapBackendInterface&RootDseHandlerInterface&MockObject $backend */
        $backend = $this->createMockForIntersectionOfInterfaces([
            LdapBackendInterface::class,
            RootDseHandlerInterface::class,
        ]);

        $this->subject = new HandlerFactory((new ServerOptions())->setBackend($backend));

        self::assertSame(
            $backend,
            $this->subject->makeRootDseHandler()
        );
    }

    public function test_it_returns_explicit_root_dse_handler_over_backend(): void
    {
        /** @var LdapBackendInterface&RootDseHandlerInterface&MockObject $backend */
        $backend = $this->createMockForIntersectionOfInterfaces([
            LdapBackendInterface::class,
            RootDseHandlerInterface::class,
        ]);
        $explicit = $this->createMock(RootDseHandlerInterface::class);

        $this->subject = new HandlerFactory(
            (new ServerOptions())
                ->setBackend($backend)
                ->setRootDseHandler($explicit)
        );

        self::assertSame($explicit, $this->subject->makeRootDseHandler());
    }

    public function test_it_returns_default_password_authenticator_when_none_is_configured(): void
    {
        $subject = new HandlerFactory(new ServerOptions());

        self::assertInstanceOf(PasswordAuthenticator::class, $subject->makePasswordAuthenticator());
    }

    public function test_it_prefers_explicitly_configured_password_authenticator(): void
    {
        $authenticator = $this->createMock(PasswordAuthenticatableInterface::class);

        $subject = new HandlerFactory(
            (new ServerOptions())->setPasswordAuthenticator($authenticator)
        );

        self::assertSame($authenticator, $subject->makePasswordAuthenticator());
    }

    public function test_it_returns_backend_as_password_authenticator_if_it_implements_the_interface(): void
    {
        /** @var LdapBackendInterface&PasswordAuthenticatableInterface&MockObject $backend */
        $backend = $this->createMockForIntersectionOfInterfaces([
            LdapBackendInterface::class,
            PasswordAuthenticatableInterface::class,
        ]);

        $subject = new HandlerFactory((new ServerOptions())->setBackend($backend));

        self::assertSame($backend, $subject->makePasswordAuthenticator());
    }

    public function test_explicit_password_authenticator_takes_precedence_over_backend(): void
    {
        $authenticator = $this->createMock(PasswordAuthenticatableInterface::class);

        /** @var LdapBackendInterface&PasswordAuthenticatableInterface&MockObject $backend */
        $backend = $this->createMockForIntersectionOfInterfaces([
            LdapBackendInterface::class,
            PasswordAuthenticatableInterface::class,
        ]);

        $subject = new HandlerFactory(
            (new ServerOptions())
                ->setBackend($backend)
                ->setPasswordAuthenticator($authenticator)
        );

        self::assertSame($authenticator, $subject->makePasswordAuthenticator());
    }
}
