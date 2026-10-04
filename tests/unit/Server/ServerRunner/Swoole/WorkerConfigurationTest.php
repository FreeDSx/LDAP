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

namespace Tests\Unit\FreeDSx\Ldap\Server\ServerRunner\Swoole;

use FreeDSx\Ldap\Server\Configuration\ConfigReloaderInterface;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\Shared\ReloadState;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\WorkerConfiguration;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class WorkerConfigurationTest extends TestCase
{
    use RequiresExtensionsTrait;

    private ConfigReloaderInterface&MockObject $reloader;

    private ServerOptions $startupOptions;

    private ServerOptions $reloadedOptions;

    private ServerProtocolFactoryInterface $startupFactory;

    private ServerProtocolFactoryInterface $reloadedFactory;

    private ReloadState $reloadState;

    /**
     * @var list<ServerListenerOptionsInterface>
     */
    private array $applied = [];

    private WorkerConfiguration $subject;

    protected function setUp(): void
    {
        $this->requireSwoole();

        $this->reloader = $this->createMock(ConfigReloaderInterface::class);
        $this->startupOptions = TestServerOptions::defaults()->setConfigReloader($this->reloader);
        $this->reloadedOptions = TestServerOptions::defaults();
        $this->startupFactory = $this->createMock(ServerProtocolFactoryInterface::class);
        $this->reloadedFactory = $this->createMock(ServerProtocolFactoryInterface::class);
        $this->reloadState = new ReloadState();

        $this->subject = new WorkerConfiguration(
            $this->startupOptions,
            $this->startupFactory,
            fn(): ServerProtocolFactoryInterface => $this->reloadedFactory,
            function (ServerListenerOptionsInterface $options): void {
                $this->applied[] = $options;
            },
            $this->reloadState,
        );
    }

    public function test_the_startup_configuration_is_served_when_no_reload_has_happened(): void
    {
        $this->reloader
            ->expects(self::never())
            ->method('reload');

        self::assertTrue($this->subject->adoptOnStart([]));
        self::assertSame(
            $this->startupOptions,
            $this->subject->options(),
        );
    }

    public function test_a_reload_since_startup_is_adopted_on_start(): void
    {
        $this->reloadState->markReloaded();
        $this->reloader
            ->method('reload')
            ->willReturn($this->reloadedOptions);

        self::assertTrue($this->subject->adoptOnStart([]));
        self::assertSame(
            $this->reloadedOptions,
            $this->subject->options(),
        );
        self::assertSame(
            $this->reloadedFactory,
            $this->subject->protocolFactory(),
        );
    }

    public function test_a_reload_that_cannot_be_adopted_on_start_refuses_to_serve(): void
    {
        $this->reloadState->markReloaded();
        $this->reloader
            ->method('reload')
            ->willThrowException(new RuntimeException('invalid'));

        self::assertFalse($this->subject->adoptOnStart([]));
        self::assertSame(
            $this->startupOptions,
            $this->subject->options(),
        );
    }

    public function test_a_successful_reload_marks_the_server_reloaded(): void
    {
        $this->reloader
            ->method('reload')
            ->willReturn($this->reloadedOptions);

        self::assertTrue($this->subject->reload([]));
        self::assertTrue($this->reloadState->hasReloaded());
        self::assertSame(
            $this->reloadedOptions,
            $this->subject->options(),
        );
    }

    public function test_a_successful_reload_is_applied_to_open_connections(): void
    {
        $this->reloader
            ->method('reload')
            ->willReturn($this->reloadedOptions);

        $this->subject->reload([]);

        self::assertSame(
            [$this->reloadedOptions],
            $this->applied,
        );
    }

    public function test_a_reload_adopted_on_start_is_applied_to_open_connections(): void
    {
        $this->reloadState->markReloaded();
        $this->reloader
            ->method('reload')
            ->willReturn($this->reloadedOptions);

        $this->subject->adoptOnStart([]);

        self::assertSame(
            [$this->reloadedOptions],
            $this->applied,
        );
    }

    public function test_a_failed_reload_applies_nothing(): void
    {
        $this->reloader
            ->method('reload')
            ->willThrowException(new RuntimeException('invalid'));

        $this->subject->reload([]);

        self::assertSame(
            [],
            $this->applied,
        );
    }

    public function test_a_failed_reload_keeps_the_configuration_and_marks_nothing(): void
    {
        $this->reloader
            ->method('reload')
            ->willThrowException(new RuntimeException('invalid'));

        self::assertFalse($this->subject->reload([]));
        self::assertFalse($this->reloadState->hasReloaded());
        self::assertSame(
            $this->startupFactory,
            $this->subject->protocolFactory(),
        );
    }
}
