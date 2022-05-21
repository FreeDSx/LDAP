<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap;

use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Socket\SocketServer;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Psr\Log\LoggerInterface;

class LdapServerSpec extends ObjectBehavior
{
    public function let(ServerRunnerInterface $serverRunner)
    {
        $this->beConstructedWith(['port' => 33389], $serverRunner);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(LdapServer::class);
    }

    public function it_should_run_the_server(ServerRunnerInterface $serverRunner)
    {
        $serverRunner->run(Argument::type(SocketServer::class))->shouldBeCalled();

        $this->run();
    }

    public function it_should_use_the_request_handler_specified(RequestHandlerInterface $requestHandler)
    {
        $this->useRequestHandler($requestHandler);

        $this->getOptions()->shouldHaveKeyWithValue('request_handler', $requestHandler);
    }

    public function it_should_use_the_rootdse_handler_specified(RootDseHandlerInterface $rootDseHandler)
    {
        $this->useRootDseHandler($rootDseHandler);

        $this->getOptions()->shouldHaveKeyWithValue('rootdse_handler', $rootDseHandler);
    }

    public function it_should_use_the_paging_handler_specified(PagingHandlerInterface $pagingHandler)
    {
        $this->usePagingHandler($pagingHandler);

        $this->getOptions()->shouldHaveKeyWithValue('paging_handler', $pagingHandler);
    }

    public function it_should_use_the_logger_specified(LoggerInterface $logger)
    {
        $this->useLogger($logger);

        $this->getOptions()->shouldHaveKeyWithValue('logger', $logger);
    }

    public function it_should_get_the_default_options_with_any_merged_values()
    {
        $this->getOptions()->shouldBeEqualTo([
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
            'ssl_cert_passphrase' => null,
            'dse_alt_server' => null,
            'dse_naming_contexts' => "dc=FreeDSx,dc=local",
            'dse_vendor_name' => "FreeDSx",
            'dse_vendor_version' => null,
        ]);
    }

    public function it_should_make_a_proxy_server()
    {
        $this->beConstructedThrough('makeProxy', ['localhost']);

        $this->getOptions()->shouldHaveKey('request_handler');
        $this->getOptions()->shouldHaveKey('paging_handler');
        $this->getOptions()->shouldHaveKey('rootdse_handler');
    }
}
