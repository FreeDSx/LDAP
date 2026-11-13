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

use FreeDSx\Ldap\Container\ContainerReloadFactory;
use FreeDSx\Ldap\Container\Provider\ClientContainerProvider;
use FreeDSx\Ldap\Container\Provider\Connection\ConnectionScaffoldingContainerProvider;
use FreeDSx\Ldap\Container\Provider\Connection\DirectoryConnectionContainerProvider;
use FreeDSx\Ldap\Container\Provider\Connection\ProxyConnectionContainerProvider;
use FreeDSx\Ldap\Container\Provider\ConnectionGraphContainerProvider;
use FreeDSx\Ldap\Container\Provider\ContainerProviderInterface;
use FreeDSx\Ldap\Container\Provider\DecoderContainerProvider;
use FreeDSx\Ldap\Container\Provider\DirectoryServerContainerProvider;
use FreeDSx\Ldap\Container\Provider\HandlerContainerProvider;
use FreeDSx\Ldap\Container\Provider\PasswordPolicyContainerProvider;
use FreeDSx\Ldap\Container\Provider\PdoStorageContainerProvider;
use FreeDSx\Ldap\Container\Provider\ProxyServerContainerProvider;
use FreeDSx\Ldap\Container\Provider\ServerListenerContainerProvider;
use FreeDSx\Ldap\Container\Provider\StorageContainerProvider;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Socket\Socket;

class Container
{
    /**
     * @param array<class-string, object> $instances
     * @param array<class-string, callable(self): object> $instanceFactory
     * @param array<class-string, callable(self): object> $connectionFactory the factories a connection scope resolves.
     */
    private function __construct(
        private array $instances,
        private readonly array $instanceFactory,
        private readonly array $connectionFactory = [],
        private readonly ?self $parent = null,
    ) {}

    /**
     * @param array<class-string, object> $sharedInstances services carried into this generation (e.g. test overrides).
     */
    public static function forClient(
        ClientOptions $options,
        ?LdapClient $client = null,
        array $sharedInstances = [],
    ): self {
        $instances = [ClientOptions::class => $options] + $sharedInstances;

        if ($client !== null) {
            $instances[LdapClient::class] = $client;
        }

        return self::root($instances);
    }

    /**
     * @param array<class-string, object> $sharedInstances services carried into this generation (e.g. across a reload).
     */
    public static function forServer(
        ServerOptions $options,
        array $sharedInstances = [],
    ): self {
        return self::root([
            ServerListenerOptionsInterface::class => $options,
            ServerOptions::class => $options,
            ContainerReloadFactory::class => new ContainerReloadFactory(
                static fn(ServerListenerOptionsInterface $reloaded, array $shared): self => self::forServer(
                    $reloaded instanceof ServerOptions
                        ? $reloaded
                        : throw new RuntimeException('A directory server can only reload into ServerOptions.'),
                    $shared,
                ),
            ),
        ] + $sharedInstances);
    }

    /**
     * @param array<class-string, object> $sharedInstances services carried into this generation (e.g. across a reload).
     */
    public static function forProxy(
        ProxyOptions $options,
        array $sharedInstances = [],
    ): self {
        return self::root([
            ServerListenerOptionsInterface::class => $options->getServerOptions(),
            ProxyServerOptions::class => $options->getServerOptions(),
            ProxyOptions::class => $options,
            ContainerReloadFactory::class => new ContainerReloadFactory(
                static fn(ServerListenerOptionsInterface $reloaded, array $shared): self => self::forProxy(
                    new ProxyOptions(
                        $reloaded instanceof ProxyServerOptions
                            ? $reloaded
                            : throw new RuntimeException('A proxy server can only reload into ProxyServerOptions.'),
                        $options->getClientOptions(),
                        $options->getUseStartTls(),
                        $options->getRequireUpstreamConfidentiality(),
                    ),
                    $shared,
                ),
            ),
        ] + $sharedInstances);
    }

    /**
     * Opens a scope holding one instance of each connection service and resolving everything else from this container.
     */
    public function forConnection(
        Socket $socket,
        ConnectionContext $context,
    ): self {
        if ($this->connectionFactory === []) {
            throw new RuntimeException('A connection scope can only be opened on a server container.');
        }

        return new self(
            instances: [
                Socket::class => $socket,
                ConnectionContext::class => $context,
            ],
            instanceFactory: $this->connectionFactory,
            parent: $this,
        );
    }

    /**
     * @template T of object
     * @param class-string<T> $className
     * @return T
     */
    public function get(string $className): object
    {
        if (isset($this->instances[$className]) && $this->instances[$className] instanceof $className) {
            return $this->instances[$className];
        }

        if (!isset($this->instanceFactory[$className])) {
            return $this->resolveUnregistered($className);
        }

        $instance = ($this->instanceFactory[$className])($this);
        if (!$instance instanceof $className) {
            throw new RuntimeException(sprintf(
                'The factory for "%s" did not return the expected type.',
                $className,
            ));
        }
        $this->instances[$className] = $instance;

        return $instance;
    }

    /**
     * Resolves a class this container has no factory for from the container its scope was opened on, or refuses it.
     *
     * @template T of object
     * @param class-string<T> $className
     * @return T
     */
    private function resolveUnregistered(string $className): object
    {
        if ($this->parent !== null) {
            return $this->parent->get($className);
        }

        if (isset($this->connectionFactory[$className])) {
            throw new RuntimeException(sprintf(
                'The class "%s" is connection scoped and can only be resolved from a connection scope.',
                $className,
            ));
        }

        throw new RuntimeException(sprintf(
            'The class "%s" is not recognized.',
            $className,
        ));
    }

    /**
     * @param array<class-string, object> $instances
     */
    private static function root(array $instances): self
    {
        $connectionFactory = self::factoriesOf(self::connectionProvidersFor($instances));
        self::refuseSeededConnectionServices(
            $instances,
            $connectionFactory,
        );

        return new self(
            $instances,
            self::factoriesOf(self::providersFor($instances)),
            $connectionFactory,
        );
    }

    /**
     * Refuses a seeded instance of a connection-scoped class.
     *
     * @param array<class-string, object> $instances
     * @param array<class-string, callable(self): object> $connectionFactory
     */
    private static function refuseSeededConnectionServices(
        array $instances,
        array $connectionFactory,
    ): void {
        $seeded = array_key_first(array_intersect_key(
            $instances,
            $connectionFactory,
        ));
        if ($seeded === null) {
            return;
        }

        throw new RuntimeException(sprintf(
            'The class "%s" is connection scoped and cannot be seeded into the container.',
            $seeded,
        ));
    }

    /**
     * The providers whose factories apply to the seeded options (client, directory server, or proxy server).
     *
     * @param array<class-string, object> $instances
     * @return ContainerProviderInterface[]
     */
    private static function providersFor(array $instances): array
    {
        $providers = [new DecoderContainerProvider()];

        if (isset($instances[ClientOptions::class])) {
            $providers[] = new ClientContainerProvider();
        }

        if (isset($instances[ServerOptions::class])) {
            $providers[] = new ServerListenerContainerProvider();
            $providers[] = new StorageContainerProvider();
            $providers[] = new PdoStorageContainerProvider();
            $providers[] = new DirectoryServerContainerProvider();
            $providers[] = new PasswordPolicyContainerProvider();
            $providers[] = new ConnectionGraphContainerProvider();
            $providers[] = new HandlerContainerProvider();
        }

        if (isset($instances[ProxyOptions::class])) {
            $providers[] = new ServerListenerContainerProvider();
            $providers[] = new ProxyServerContainerProvider();
        }

        return $providers;
    }

    /**
     * The providers whose factories a connection scope resolves for the seeded options.
     *
     * @param array<class-string, object> $instances
     * @return ContainerProviderInterface[]
     */
    private static function connectionProvidersFor(array $instances): array
    {
        if (isset($instances[ServerOptions::class])) {
            return [
                new ConnectionScaffoldingContainerProvider(),
                new DirectoryConnectionContainerProvider(),
            ];
        }

        if (isset($instances[ProxyOptions::class])) {
            return [
                new ConnectionScaffoldingContainerProvider(),
                new ProxyConnectionContainerProvider(),
            ];
        }

        return [];
    }

    /**
     * @param ContainerProviderInterface[] $providers
     * @return array<class-string, callable(self): object>
     */
    private static function factoriesOf(array $providers): array
    {
        $factories = [];
        foreach ($providers as $provider) {
            $factories = [
                ...$factories,
                ...$provider->factories(),
            ];
        }

        return $factories;
    }
}
