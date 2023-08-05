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

namespace spec\FreeDSx\Ldap;

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
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Psr\Log\LoggerInterface;

class LdapServerSpec extends ObjectBehavior
{
    public function let(ServerRunnerInterface $serverRunner): void
    {
        $this->beConstructedWith(
            (new ServerOptions())->setPort(33389),
            $serverRunner
        );
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(LdapServer::class);
    }

    public function it_should_run_the_server(ServerRunnerInterface $serverRunner): void
    {
        $serverRunner->run(Argument::type(SocketServer::class))
            ->shouldBeCalled();

        $this->run();
    }

    public function it_should_use_the_request_handler_specified(RequestHandlerInterface $requestHandler): void
    {
        $this->useRequestHandler($requestHandler);

        $this->getOptions()
            ->getRequestHandler()
            ->shouldBeEqualTo($requestHandler);
    }

    public function it_should_use_the_rootdse_handler_specified(RootDseHandlerInterface $rootDseHandler): void
    {
        $this->useRootDseHandler($rootDseHandler);

        $this->getOptions()
            ->getRootDseHandler()
            ->shouldBeEqualTo($rootDseHandler);
    }

    public function it_should_use_the_paging_handler_specified(PagingHandlerInterface $pagingHandler): void
    {
        $this->usePagingHandler($pagingHandler);

        $this->getOptions()
            ->getPagingHandler()
            ->shouldBeEqualTo($pagingHandler);
    }

    public function it_should_use_the_logger_specified(LoggerInterface $logger): void
    {
        $this->useLogger($logger);

        $this->getOptions()
            ->getLogger()
            ->shouldBeEqualTo($logger);
    }

    public function it_should_get_the_default_options(): void
    {
        $this->getOptions()
            ->toArray()
            ->shouldBeEqualTo([
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
            ]);
    }

    public function it_should_make_a_proxy_server(): void
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

        $proxyOptions = $this::makeProxy('localhost')
            ->getOptions();

        $proxyOptions->getPagingHandler()
            ->shouldBeAnInstanceOf(ProxyPagingHandler::class);
        $proxyOptions
            ->getRequestHandler()
            ->shouldBeAnInstanceOf(ProxyRequestHandler::class);
        $proxyOptions
            ->getRootDseHandler()
            ->shouldBeAnInstanceOf(ProxyRequestHandler::class);
    }
}
