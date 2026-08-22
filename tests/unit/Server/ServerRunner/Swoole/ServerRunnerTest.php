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

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\ServerProtocolFactory;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\PooledServerRunner;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\ServerRunner;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\WorkerFactory;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use PHPUnit\Framework\TestCase;

final class ServerRunnerTest extends TestCase
{
    private WorkerFactory $workers;

    protected function setUp(): void
    {
        $factory = $this->createMock(ServerProtocolFactory::class);

        $this->workers = new WorkerFactory(
            serverProtocolFactory: $factory,
            options: TestServerOptions::defaults(),
            socketServerFactory: $this->createMock(SocketServerFactory::class),
            protocolFactoryProvider: static fn(ServerListenerOptionsInterface $options) => $factory,
        );
    }

    public function test_constructor_throws_when_swoole_not_loaded(): void
    {
        if (extension_loaded('swoole')) {
            $this->markTestSkipped('This test requires the swoole extension to NOT be loaded.');
        }

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/Swoole extension/');

        new ServerRunner($this->workers);
    }

    public function test_a_pool_refuses_to_run_a_single_worker(): void
    {
        if (!extension_loaded('swoole')) {
            $this->markTestSkipped('The swoole extension is required.');
        }

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/more than one worker/');

        new PooledServerRunner(
            $this->workers,
            1,
        );
    }
}
