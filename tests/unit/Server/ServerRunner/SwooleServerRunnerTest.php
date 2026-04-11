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

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\ServerProtocolFactory;
use FreeDSx\Ldap\Server\ServerRunner\SwooleServerRunner;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;

final class SwooleServerRunnerTest extends TestCase
{
    public function test_constructor_throws_when_swoole_not_loaded(): void
    {
        if (extension_loaded('swoole')) {
            $this->markTestSkipped('This test requires the swoole extension to NOT be loaded.');
        }

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/Swoole extension/');

        new SwooleServerRunner(
            serverProtocolFactory: $this->createMock(ServerProtocolFactory::class),
            options: new ServerOptions(),
            socketServerFactory: $this->createMock(SocketServerFactory::class),
        );
    }
}
