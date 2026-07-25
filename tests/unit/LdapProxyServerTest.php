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

namespace Tests\Unit\FreeDSx\Ldap;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\LdapProxyServer;
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\ProxyServerOptions;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class LdapProxyServerTest extends TestCase
{
    private ProxyOptions $options;

    private ServerRunnerInterface&MockObject $mockServerRunner;

    private LdapProxyServer $subject;

    protected function setUp(): void
    {
        $this->options = new ProxyOptions(
            new ProxyServerOptions(),
            new ClientOptions(['localhost']),
        );
        $this->mockServerRunner = $this->createMock(ServerRunnerInterface::class);
        $this->subject = new LdapProxyServer(
            $this->options,
            Container::forProxy(
                $this->options,
                [ServerRunnerInterface::class => $this->mockServerRunner],
            ),
        );
    }

    public function test_it_exposes_its_options(): void
    {
        self::assertSame(
            $this->options,
            $this->subject->getOptions(),
        );
    }

    public function test_it_runs_the_server_via_the_container_runner(): void
    {
        $this->mockServerRunner
            ->expects(self::once())
            ->method('run');

        $this->subject->run();
    }
}
