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
use FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\ProxyHandler;
use FreeDSx\Ldap\Server\RequestHandler\ProxyPagingHandler;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\ServerRunner\PcntlServerRunner;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Socket\Exception\ConnectionException;
use FreeDSx\Socket\SocketServer;
use Psr\Log\LoggerInterface;

/**
 * The LDAP server.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapServer
{
    use LoggerTrait;

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
        'paging_handler' => null,
        'logger' => null,
        'use_ssl' => false,
        'ssl_cert' => null,
        'ssl_cert_passphrase' => null,
        'dse_alt_server' => null,
        'dse_naming_contexts' => 'dc=FreeDSx,dc=local',
        'dse_vendor_name' => 'FreeDSx',
        'dse_vendor_version' => null,
    ];

    /**
     * @var ServerRunnerInterface|null
     */
    protected $runner;

    /**
     * @param array $options
     * @param ServerRunnerInterface|null $serverRunner
     * @throws RuntimeException
     */
    public function __construct(
        array $options = [],
        ?ServerRunnerInterface $serverRunner = null
    ) {
        $this->options = array_merge(
            $this->options,
            $options
        );
        $this->runner = $serverRunner;
    }

    /**
     * Runs the LDAP server. Binds the socket on the request IP/port and sends it to the server runner.
     *
     * @throws ConnectionException
     */
    public function run(): void
    {
        $isUnixSocket = $this->options['transport'] === 'unix';
        $resource = $isUnixSocket
            ? $this->options['unix_socket']
            : $this->options['ip'];

        if ($isUnixSocket) {
            $this->removeExistingSocketIfNeeded($resource);
        }

        $socketServer = SocketServer::bind(
            $resource,
            $this->options['port'],
            $this->options
        );

        $this->runner()->run($socketServer);
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

    /**
     * Specify an instance of a paging handler to use for paged search requests.
     *
     * @param PagingHandlerInterface $pagingHandler
     * @return $this
     */
    public function usePagingHandler(PagingHandlerInterface $pagingHandler): self
    {
        $this->options['paging_handler'] = $pagingHandler;

        return $this;
    }

    /**
     * Specify a logger to be used by the server process.
     */
    public function useLogger(LoggerInterface $logger): self
    {
        $this->options['logger'] = $logger;

        return $this;
    }

    /**
     * Convenience method for generating an LDAP server instance that will proxy client request's to an LDAP server.
     *
     * Note: This is only intended to work with the PCNTL server runner.
     *
     * @param string|string[] $servers The LDAP server(s) to proxy the request to.
     * @param array<string, mixed> $clientOptions Any additional client options for the proxy connection.
     * @param array<string, mixed> $serverOptions Any additional server options for the LDAP server.
     * @return LdapServer
     */
    public static function makeProxy(
        $servers,
        array $clientOptions = [],
        array $serverOptions = []
    ): LdapServer {
        $client = new LdapClient(array_merge([
            'servers' => $servers,
        ], $clientOptions));

        $proxyRequestHandler = new ProxyHandler($client);
        $server = new LdapServer($serverOptions);
        $server->useRequestHandler($proxyRequestHandler);
        $server->useRootDseHandler($proxyRequestHandler);
        $server->usePagingHandler(new ProxyPagingHandler($client));

        return $server;
    }

    private function runner(): ServerRunnerInterface
    {
        if (!$this->runner) {
            $this->runner = new PcntlServerRunner($this->options);
        }

        return $this->runner;
    }

    private function removeExistingSocketIfNeeded(string $socket): void
    {
        if (!file_exists($socket)) {
            return;
        }

        if (!is_writeable($socket)) {
            $this->logAndThrow(sprintf(
                'The socket "%s" already exists and is not writeable. To run the LDAP server, you must remove the existing socket.',
                $socket
            ));
        }

        if (!unlink($socket)) {
            $this->logAndThrow(sprintf(
                'The existing socket "%s" could not be removed. To run the LDAP server, you must remove the existing socket.',
                $socket
            ));
        }
    }
}
