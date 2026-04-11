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

use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\ProxyHandler;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Socket\Exception\ConnectionException;
use Psr\Log\LoggerInterface;

/**
 * The LDAP server.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapServer
{
    private Container $container;

    public function __construct(
        private readonly ServerOptions $options = new ServerOptions(),
        ?Container $container = null,
    ) {
        $this->container = $container ?? new Container([
            ServerOptions::class => $this->options,
        ]);
    }

    /**
     * Runs the LDAP server. Binds the socket and starts accepting client connections.
     *
     * @throws ConnectionException
     */
    public function run(): void
    {
        $runner = $this->options->getServerRunner() ?? $this->container->get(ServerRunnerInterface::class);

        $runner->run();
    }

    /**
     * Get the options currently set for the LDAP server.
     */
    public function getOptions(): ServerOptions
    {
        return $this->options;
    }

    /**
     * Specify an entry storage implementation to back the LDAP server.
     *
     * Use useBackend() instead when implementing a fully custom backend (e.g.
     * a proxy) that handles LDAP semantics itself.
     */
    public function useStorage(EntryStorageInterface $storage): self
    {
        return $this->useBackend(new WritableStorageBackend($storage));
    }

    /**
     * Specify a backend to use for incoming LDAP requests.
     */
    public function useBackend(LdapBackendInterface $backend): self
    {
        $this->options->setBackend($backend);

        return $this;
    }

    /**
     * Override the password authenticator used for simple bind and SASL PLAIN.
     */
    public function usePasswordAuthenticator(PasswordAuthenticatableInterface $authenticator): self
    {
        $this->options->setPasswordAuthenticator($authenticator);

        return $this;
    }

    /**
     * Register a handler for one or more LDAP write operations.
     */
    public function useWriteHandler(WriteHandlerInterface $handler): self
    {
        $this->options->addWriteHandler($handler);

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
     * Override the filter evaluator used by the server when applying LDAP filters
     * to entries returned by the backend's search() generator.
     */
    public function useFilterEvaluator(FilterEvaluatorInterface $evaluator): self
    {
        $this->options->setFilterEvaluator($evaluator);

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
     * Configure the server to use the Swoole coroutine runner instead of the default PCNTL process runner.
     *
     * Requires the swoole PHP extension. The SwooleServerRunner handles each client connection in its own
     * coroutine within a single process, making in-memory storage adapters safe to use concurrently.
     */
    public function useSwooleRunner(): self
    {
        $this->options->setUseSwooleRunner(true);

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

        $server = new LdapServer($serverOptions);
        $server->useBackend(new ProxyHandler($client));

        return $server;
    }
}
