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

namespace FreeDSx\Ldap;

use FreeDSx\Ldap\Server\LoggerTrait;
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

    public function __construct(
        private readonly ServerOptions $options = new ServerOptions(),
        private ?ServerRunnerInterface $runner = null
    ) {
    }

    /**
     * Runs the LDAP server. Binds the socket on the request IP/port and sends it to the server runner.
     *
     * @throws ConnectionException
     */
    public function run(): void
    {
        $isUnixSocket = $this->options->getTransport() === 'unix';
        $resource = $isUnixSocket
            ? $this->options->getUnixSocket()
            : $this->options->getIp();

        if ($isUnixSocket) {
            $this->removeExistingSocketIfNeeded($resource);
        }

        $socketServer = SocketServer::bind(
            $resource,
            $this->options->getPort(),
            $this->options->toArray(),
        );

        $this->runner()->run($socketServer);
    }

    /**
     * Get the options currently set for the LDAP server.
     */
    public function getOptions(): ServerOptions
    {
        return $this->options;
    }

    /**
     * Specify an instance of a request handler to use for incoming LDAP requests.
     */
    public function useRequestHandler(RequestHandlerInterface $requestHandler): self
    {
        $this->options->setRequestHandler($requestHandler);

        return $this;
    }

    /**
     * Specify an instance of a RootDSE handler to use for RootDSE requests.
     */
    public function useRootDseHandler(RootDseHandlerInterface $rootDseHandler): self
    {
        $this->options->setRootDseHandler($rootDseHandler);

        return $this;
    }

    /**
     * Specify an instance of a paging handler to use for paged search requests.
     */
    public function usePagingHandler(PagingHandlerInterface $pagingHandler): self
    {
        $this->options->setPagingHandler($pagingHandler);

        return $this;
    }

    /**
     * Specify a logger to be used by the server process.
     */
    public function useLogger(LoggerInterface $logger): self
    {
        $this->options->setLogger($logger);

        return $this;
    }

    /**
     * Convenience method for generating an LDAP server instance that will proxy client request's to an LDAP server.
     *
     * Note: This is only intended to work with the PCNTL server runner.
     *
     * @param string|string[] $servers The LDAP server(s) to proxy the request to.
     * @param ClientOptions $clientOptions Any additional client options for the proxy connection.
     * @param ServerOptions $serverOptions Any additional server options for the LDAP server.
     */
    public static function makeProxy(
        array|string $servers,
        ClientOptions $clientOptions = new ClientOptions(),
        ServerOptions $serverOptions = new ServerOptions(),
    ): LdapServer {
        $client = new LdapClient(
            $clientOptions->setServers((array) $servers)
        );

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
