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

namespace Tests\Unit\FreeDSx\Ldap\Server\ServerRunner;

use FreeDSx\Ldap\Server\Configuration\ConfigReloaderInterface;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\ServerRunner\RunnerConfiguration;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class RunnerConfigurationTest extends TestCase
{
    private ConfigReloaderInterface&MockObject $reloader;

    private ServerOptions $startupOptions;

    private ServerOptions $reloadedOptions;

    private ServerProtocolFactoryInterface $startupFactory;

    private ServerProtocolFactoryInterface $reloadedFactory;

    /**
     * @var list<ServerListenerOptionsInterface>
     */
    private array $applied = [];

    private RunnerConfiguration $subject;

    protected function setUp(): void
    {
        $this->reloader = $this->createMock(ConfigReloaderInterface::class);
        $this->startupOptions = TestServerOptions::defaults()->setConfigReloader($this->reloader);
        $this->reloadedOptions = TestServerOptions::defaults();
        $this->startupFactory = $this->createMock(ServerProtocolFactoryInterface::class);
        $this->reloadedFactory = $this->createMock(ServerProtocolFactoryInterface::class);

        $this->subject = new RunnerConfiguration(
            $this->startupOptions,
            $this->startupFactory,
            fn(): ServerProtocolFactoryInterface => $this->reloadedFactory,
            function (ServerListenerOptionsInterface $options): void {
                $this->applied[] = $options;
            },
        );
    }

    public function test_a_reload_replaces_what_new_connections_are_served_under_and_applies_it_to_open_ones(): void
    {
        $this->reloader
            ->method('reload')
            ->willReturn($this->reloadedOptions);

        self::assertTrue($this->subject->reload([]));
        self::assertSame(
            [$this->reloadedOptions, $this->reloadedFactory],
            [$this->subject->options(), $this->subject->protocolFactory()],
        );
        self::assertSame(
            [$this->reloadedOptions],
            $this->applied,
        );
    }

    public function test_a_failed_reload_keeps_the_configuration_and_applies_nothing(): void
    {
        $this->reloader
            ->method('reload')
            ->willThrowException(new RuntimeException('invalid'));

        self::assertFalse($this->subject->reload([]));
        self::assertSame(
            [$this->startupOptions, $this->startupFactory],
            [$this->subject->options(), $this->subject->protocolFactory()],
        );
        self::assertSame(
            [],
            $this->applied,
        );
    }

    public function test_following_a_reload_applies_it_to_open_connections_without_rebuilding_for_new_ones(): void
    {
        $this->reloader
            ->method('reload')
            ->willReturn($this->reloadedOptions);

        self::assertTrue($this->subject->follow([]));
        self::assertSame(
            [$this->reloadedOptions],
            $this->applied,
        );
        self::assertSame(
            $this->startupFactory,
            $this->subject->protocolFactory(),
        );
    }

    public function test_a_reload_that_cannot_be_followed_applies_nothing(): void
    {
        $this->reloader
            ->method('reload')
            ->willThrowException(new RuntimeException('invalid'));

        self::assertFalse($this->subject->follow([]));
        self::assertSame(
            [],
            $this->applied,
        );
    }
}
