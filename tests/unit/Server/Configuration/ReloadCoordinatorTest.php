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

namespace Tests\Unit\FreeDSx\Ldap\Server\Configuration;

use FreeDSx\Ldap\Server\Configuration\ConfigReloaderInterface;
use FreeDSx\Ldap\Server\Configuration\ReloadCoordinator;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use RuntimeException;

final class ReloadCoordinatorTest extends TestCase
{
    private ReloadCoordinator $subject;

    private ServerProtocolFactoryInterface $reloadedFactory;

    protected function setUp(): void
    {
        $this->subject = new ReloadCoordinator();
        $this->reloadedFactory = $this->createMock(ServerProtocolFactoryInterface::class);
    }

    public function test_reload_returns_the_new_options_and_a_factory_rebuilt_from_them(): void
    {
        $newOptions = new ServerOptions(networkConfig: (new NetworkConfig())->setMaxConnections(123));
        $reloader = $this->createMock(ConfigReloaderInterface::class);
        $reloader
            ->expects(self::once())
            ->method('reload')
            ->willReturn($newOptions);

        $rebuiltFrom = null;
        $result = $this->subject->reload(
            (new ServerOptions())->setConfigReloader($reloader),
            function (ServerListenerOptionsInterface $options) use (&$rebuiltFrom): ServerProtocolFactoryInterface {
                $rebuiltFrom = $options;

                return $this->reloadedFactory;
            },
        );

        self::assertNotNull($result);
        self::assertSame(
            $newOptions,
            $result->options,
        );
        self::assertSame(
            $this->reloadedFactory,
            $result->protocolFactory,
        );
        self::assertSame(
            $newOptions,
            $rebuiltFrom,
        );
    }

    public function test_a_missing_config_reloader_is_a_logged_no_op(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger
            ->expects(self::once())
            ->method('log')
            ->with(
                LogLevel::INFO,
                self::stringContains('no configuration reloader'),
                self::anything(),
            );

        $result = $this->subject->reload(
            (new ServerOptions())->setLogger($logger),
            fn(ServerListenerOptionsInterface $options) => $this->reloadedFactory,
        );

        self::assertNull($result);
    }

    public function test_a_failing_reload_returns_null_and_logs_an_error(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger
            ->expects(self::once())
            ->method('log')
            ->with(
                LogLevel::ERROR,
                self::stringContains('reload failed'),
                self::anything(),
            );

        $reloader = $this->createMock(ConfigReloaderInterface::class);
        $reloader
            ->method('reload')
            ->willThrowException(new RuntimeException('Bad configuration.'));

        $result = $this->subject->reload(
            (new ServerOptions())
                ->setLogger($logger)
                ->setConfigReloader($reloader),
            fn(ServerListenerOptionsInterface $options) => $this->reloadedFactory,
        );

        self::assertNull($result);
    }
}
