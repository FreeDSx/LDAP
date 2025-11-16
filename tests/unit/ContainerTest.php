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
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ClientQueueInstantiator;
use FreeDSx\Ldap\Protocol\RootDseLoader;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\ServerProtocolFactory;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\SocketPool;
use PHPUnit\Framework\TestCase;

class ContainerTest extends TestCase
{
    private Container $subject;

    protected function setUp(): void
    {
        parent::setUp();

        $client = new LdapClient();
        $serverOptions = new ServerOptions();

        $this->subject = new Container([
            LdapClient::class => $client,
            ClientOptions::class => $client->getOptions(),
            ServerOptions::class => $serverOptions,
        ]);
    }

    public static function buildableDependenciesDataProvider(): array
    {
        return [
            [LdapClient::class],
            [ClientProtocolHandler::class],
            [ClientQueueInstantiator::class],
            [ClientProtocolHandlerFactory::class],
            [SocketPool::class],
            [RootDseLoader::class],
            [ServerProtocolFactory::class],
            [HandlerFactoryInterface::class],
            [ServerAuthorization::class],
            [SocketServerFactory::class],
        ];
    }

    /**
     * @param class-string $class
     *
     * @dataProvider buildableDependenciesDataProvider
     */
    public function test_it_builds_the_dependencies(
        string $class,
    ): void {
        self::assertInstanceOf(
            $class,
            $this->subject->get($class),
        );
    }

    public function test_it_should_make_the_default_ServerRunner(): void
    {
        if (str_starts_with(strtoupper(PHP_OS), 'WIN')) {
            self::markTestSkipped('Cannot construct the default PCNTL runner on Windows.');
        }

        self::assertInstanceOf(
            ServerRunnerInterface::class,
            $this->subject->get(ServerRunnerInterface::class),
        );
    }
}
