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

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\ProxyHandler;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\SaslHandlerInterface;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Server\SocketServerFactory;
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
     * Runs the LDAP server. Binds the socket on the request IP/port and sends it to the server runner.
     *
     * @throws ConnectionException
     * @throws InvalidArgumentException
     */
    public function run(): void
    {
        $this->validateSaslConfiguration();

        $socketServer = $this->container
            ->get(SocketServerFactory::class)
            ->makeAndBind();

        $runner = $this->options->getServerRunner() ?? $this->container->get(ServerRunnerInterface::class);

        $runner->run($socketServer);
    }

    /**
     * Get the options currently set for the LDAP server.
     */
    public function getOptions(): ServerOptions
    {
        return $this->options;
    }

    /**
     * Specify a backend to use for incoming LDAP requests.
     *
     * The backend handles search and optionally write operations (add, delete,
     * modify, rename) if it implements WritableLdapBackendInterface. Bind
     * authentication is handled by a PasswordAuthenticatableInterface — either
     * one registered via usePasswordAuthenticator(), the backend itself if it
     * implements that interface, or the default PasswordAuthenticator (which
     * reads the userPassword attribute from entries returned by the backend).
     */
    public function useBackend(LdapBackendInterface $backend): self
    {
        $this->options->setBackend($backend);

        return $this;
    }

    /**
     * Override the password authenticator used for simple bind and SASL PLAIN.
     *
     * By default the server constructs a PasswordAuthenticator that reads the
     * userPassword attribute from entries returned by the backend. Use this
     * method to supply a custom implementation — for example, to support
     * additional hash formats or to delegate verification to an external service.
     */
    public function usePasswordAuthenticator(PasswordAuthenticatableInterface $authenticator): self
    {
        $this->options->setPasswordAuthenticator($authenticator);

        return $this;
    }

    /**
     * Register a handler for one or more LDAP write operations.
     *
     * Handlers are tried in registration order, before the backend is used as
     * a fallback. Multiple calls register multiple handlers, allowing each
     * write operation to be handled by a separate class.
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
     * Validates that the SASL configuration is consistent before the server starts.
     *
     * @throws InvalidArgumentException
     */
    private function validateSaslConfiguration(): void
    {
        $challengeMechanisms = array_diff(
            $this->options->getSaslMechanisms(),
            [ServerOptions::SASL_PLAIN],
        );

        if (empty($challengeMechanisms)) {
            return;
        }

        $backend = $this->options->getBackend();

        if (!$backend instanceof SaslHandlerInterface) {
            throw new InvalidArgumentException(sprintf(
                'The SASL mechanism(s) [%s] require the backend to implement %s.',
                implode(', ', $challengeMechanisms),
                SaslHandlerInterface::class,
            ));
        }
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
