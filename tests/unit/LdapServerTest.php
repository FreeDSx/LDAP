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
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\ProxyHandler;
use FreeDSx\Ldap\Server\RequestHandler\ProxyPagingHandler;
use FreeDSx\Ldap\Server\RequestHandler\ProxyRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\SocketServer;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class LdapServerTest extends TestCase
{
    private LdapServer $subject;

    private ServerOptions $options;

    private ServerRunnerInterface&MockObject $mockServerRunner;

    protected function setUp(): void
    {
        $this->mockServerRunner = $this->createMock(ServerRunnerInterface::class);

        $this->options = (new ServerOptions())
            ->setPort(33389)
            ->setServerRunner($this->mockServerRunner);

        $this->subject = new LdapServer($this->options);
    }

    public function test_it_should_run_the_server(): void
    {
        $this->mockServerRunner
            ->expects(self::once())
            ->method('run')
            ->with(self::isInstanceOf(SocketServer::class));

        $this->subject->run();
    }

    public function test_it_should_use_the_request_handler_specified(): void
    {
        $requestHandler = $this->createMock(RequestHandlerInterface::class);

        $this->subject->useRequestHandler($requestHandler);

        self::assertSame(
            $requestHandler,
            $this->subject->getOptions()
                ->getRequestHandler()
        );
    }

    public function test_it_should_use_the_rootdse_handler_specified(): void
    {
        $rootDseHandler = $this->createMock(RootDseHandlerInterface::class);

        $this->subject->useRootDseHandler($rootDseHandler);

        self::assertSame(
            $rootDseHandler,
            $this->subject->getOptions()
                ->getRootDseHandler()
        );
    }

    public function test_it_should_use_the_paging_handler_specified(): void
    {
        $pagingHandler = $this->createMock(PagingHandlerInterface::class);

        $this->subject->usePagingHandler($pagingHandler);

        self::assertSame(
            $pagingHandler,
            $this->subject->getOptions()
                ->getPagingHandler()
        );
    }

    public function test_it_should_use_the_logger_specified(): void
    {
        $logger = $this->createMock(LoggerInterface::class);

        $this->subject->useLogger($logger);

        self::assertSame(
            $logger,
            $this->subject->getOptions()
                ->getLogger()
        );
    }

    public function test_it_should_get_the_default_options(): void
    {
        self::assertEquals(
            [
                'ip' => "0.0.0.0",
                'port' => 33389,
                'unix_socket' => "/var/run/ldap.socket",
                'transport' => "tcp",
                'idle_timeout' => 600,
                'require_authentication' => true,
                'allow_anonymous' => false,
                'request_handler' => null,
                'rootdse_handler' => null,
                'paging_handler' => null,
                'logger' => null,
                'use_ssl' => false,
                'ssl_cert' => null,
                'ssl_cert_key' => null,
                'ssl_cert_passphrase' => null,
                'dse_alt_server' => null,
                'dse_naming_contexts' => [
                    "dc=FreeDSx,dc=local"
                ],
                'dse_vendor_name' => "FreeDSx",
                'dse_vendor_version' => null,
            ],
            $this->subject->getOptions()->toArray(),
        );
    }

    public function test_it_should_make_a_proxy_server(): void
    {
        $client = new LdapClient(
            (new ClientOptions())
                ->setServers(['localhost'])
        );
        $serverOptions = new ServerOptions();
        $proxyRequestHandler = new ProxyHandler($client);
        $server = new LdapServer($serverOptions);
        $server->useRequestHandler($proxyRequestHandler);
        $server->useRootDseHandler($proxyRequestHandler);
        $server->usePagingHandler(new ProxyPagingHandler($client));

        $proxyOptions = LdapServer::makeProxy('localhost')
            ->getOptions();

        self::assertInstanceOf(
            ProxyPagingHandler::class,
            $proxyOptions->getPagingHandler()
        );
        self::assertInstanceOf(
            ProxyRequestHandler::class,
            $proxyOptions->getRequestHandler()
        );
        self::assertInstanceOf(
            ProxyRequestHandler::class,
            $proxyOptions->getRootDseHandler(),
        );
    }
}
