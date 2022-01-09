<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\ServerRunner\PcntlServerRunner;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Socket\Exception\ConnectionException;
use FreeDSx\Socket\SocketServer;

/**
 * The LDAP server.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapServer
{
    /**
     * @var array
     */
    protected $options = [
        'ip' => '0.0.0.0',
        'port' => 389,
        'unix_socket' => '/var/run/ldap.socket',
        'transport' => 'tcp',
        'idle_timeout' => 600,
        'require_authentication' => true,
        'allow_anonymous' => false,
        'request_handler' => null,
        'rootdse_handler' => null,
        'use_ssl' => false,
        'ssl_cert' => null,
        'ssl_cert_passphrase' => null,
        'dse_alt_server' => null,
        'dse_naming_contexts' => 'dc=FreeDSx,dc=local',
        'dse_vendor_name' => 'FreeDSx',
        'dse_vendor_version' => null,
    ];

    /**
     * @var ServerRunnerInterface
     */
    protected $runner;

    /**
     * @param array $options
     * @param ServerRunnerInterface|null $serverRunner
     * @throws RuntimeException
     */
    public function __construct(
        array $options = [],
        ServerRunnerInterface $serverRunner = null
    ) {
        $this->options = array_merge(
            $this->options,
            $options
        );
        $this->runner = $serverRunner ?? new PcntlServerRunner($this->options);
    }

    /**
     * Runs the LDAP server. Binds the socket on the request IP/port and sends it to the server runner.
     *
     * @throws ConnectionException
     */
    public function run(): void
    {
        $resource = $this->options['transport'] === 'unix'
            ? $this->options['unix_socket']
            : $this->options['ip'];

        $this->runner->run(SocketServer::bind(
            $resource,
            $this->options['port'],
            $this->options
        ));
    }

    /**
     * Get the options currently set for the LDAP server.
     *
     * @return array<string, mixed>
     */
    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * Specify an instance of a request handler to use for incoming LDAP requests.
     *
     * @param RequestHandlerInterface $requestHandler
     * @return $this
     */
    public function useRequestHandler(RequestHandlerInterface $requestHandler): self
    {
        $this->options['request_handler'] = $requestHandler;

        return $this;
    }

    /**
     * Specify an instance of a RootDSE handler to use for RootDSE requests.
     *
     * @param RootDseHandlerInterface $rootDseHandler
     * @return $this
     */
    public function useRootDseHandler(RootDseHandlerInterface $rootDseHandler): self
    {
        $this->options['rootdse_handler'] = $rootDseHandler;

        return $this;
    }
}
