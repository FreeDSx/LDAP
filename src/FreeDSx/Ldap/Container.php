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
use FreeDSx\Ldap\Container\Provider\ConnectionGraphContainerProvider;
use FreeDSx\Ldap\Container\Provider\ContainerProviderInterface;
use FreeDSx\Ldap\Container\Provider\DirectoryServerContainerProvider;
use FreeDSx\Ldap\Container\Provider\HandlerContainerProvider;
use FreeDSx\Ldap\Container\Provider\PasswordPolicyContainerProvider;
use FreeDSx\Ldap\Container\Provider\ProxyServerContainerProvider;
use FreeDSx\Ldap\Container\Provider\ServerListenerContainerProvider;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;

use function in_array;

class Container
{
    /**
     * These are classes that should never cache an instance when retrieved from the container.
     */
    private const FACTORY_ONLY = [
        HandlerFactoryInterface::class,
        ServerAuthorization::class,
    ];

    /**
     * @var array<class-string, callable(self): object>
     */
    private array $instanceFactory = [];

    /**
     * @var array<class-string, object>
     */
    private array $instances = [];

    /**
     * @param array<class-string, object> $instances
     */
    private function __construct(array $instances)
    {
        foreach ($instances as $className => $instance) {
            $this->instances[$className] = $instance;
        }

        foreach ($this->providers() as $provider) {
            foreach ($provider->factories() as $className => $factory) {
                $this->registerFactory(
                    $className,
                    $factory,
                );
            }
        }
    }

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

        return new self($instances);
    }

    /**
     * @param array<class-string, object> $sharedInstances services carried into this generation (e.g. across a reload).
     */
    public static function forServer(
        ServerOptions $options,
        array $sharedInstances = [],
    ): self {
        return new self([
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
        return new self([
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
                    ),
                    $shared,
                ),
            ),
        ] + $sharedInstances);
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
            throw new RuntimeException(sprintf(
                'The class "%s" is not recognized.',
                $className,
            ));
        }

        $instance = ($this->instanceFactory[$className])($this);
        if (!$instance instanceof $className) {
            throw new RuntimeException(sprintf(
                'The factory for "%s" did not return the expected type.',
                $className,
            ));
        }

        if (!in_array($className, self::FACTORY_ONLY, true)) {
            $this->instances[$className] = $instance;
        }

        return $instance;
    }

    /**
     * The providers whose factories apply to the seeded options (client, directory server, or proxy server).
     *
     * @return ContainerProviderInterface[]
     */
    private function providers(): array
    {
        $providers = [];

        if (isset($this->instances[ClientOptions::class])) {
            $providers[] = new ClientContainerProvider();
        }

        if (isset($this->instances[ServerOptions::class])) {
            $providers[] = new ServerListenerContainerProvider();
            $providers[] = new DirectoryServerContainerProvider();
            $providers[] = new PasswordPolicyContainerProvider();
            $providers[] = new ConnectionGraphContainerProvider();
            $providers[] = new HandlerContainerProvider();
        }

        if (isset($this->instances[ProxyOptions::class])) {
            $providers[] = new ServerListenerContainerProvider();
            $providers[] = new ProxyServerContainerProvider();
        }

        return $providers;
    }

    /**
     * @param class-string $className
     * @param callable(self): object $factory
     */
    private function registerFactory(
        string $className,
        callable $factory,
    ): void {
        $this->instanceFactory[$className] = $factory;
    }
}
