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

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ClientQueueInstantiator;
use FreeDSx\Ldap\Protocol\RootDseLoader;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\RequestHandler\HandlerFactory;
use FreeDSx\Ldap\Server\RequestHistory;
use FreeDSx\Ldap\Server\ServerProtocolFactory;
use FreeDSx\Ldap\Server\ServerRunner\PcntlServerRunner;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Socket\SocketPool;

class Container
{
    /**
     * @var array<class-string, callable>
     */
    private array $instanceFactory = [];

    /**
     * These are classes that should never cache an instance when retrieved from the container.
     */
    private const FACTORY_ONLY = [
        HandlerFactoryInterface::class,
        ServerAuthorization::class,
        ServerProtocolHandlerFactory::class,
    ];

    /**
     * @var array<class-string, object>
     */
    private array $instances = [];

    /**
     * @param array<class-string, object> $instances
     */
    public function __construct(array $instances)
    {
        foreach ($instances as $className => $instance) {
            $this->instances[$className] = $instance;
        }

        $this->registerClientClasses();
        $this->registerServerClasses();
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
                $className
            ));
        }

        $instance = ($this->instanceFactory[$className])();
        if (!in_array($className, self::FACTORY_ONLY, true)) {
            $this->instances[$className] = $instance;
        }

        return $instance;
    }

    /**
     * @param class-string $className
     */
    private function registerFactory(
        string $className,
        callable $factory,
    ): void {
        $this->instanceFactory[$className] = $factory;
    }

    private function registerClientClasses(): void
    {
        if (!isset($this->instances[ClientOptions::class])) {
            return;
        }

        $this->registerFactory(
            className: ClientProtocolHandler::class,
            factory: $this->makeClientProtocolHandler(...),
        );
        $this->registerFactory(
            className: SocketPool::class,
            factory: $this->makeSocketPool(...),
        );
        $this->registerFactory(
            className: ClientProtocolHandlerFactory::class,
            factory: $this->makeClientProtocolHandlerFactory(...),
        );
        $this->registerFactory(
            className: ClientQueueInstantiator::class,
            factory: $this->makeClientQueueInstantiator(...)
        );
        $this->registerFactory(
            className: RootDseLoader::class,
            factory: $this->makeRootDseLoader(...),
        );
    }

    private function registerServerClasses(): void
    {
        if (!isset($this->instances[ServerOptions::class])) {
            return;
        }

        $this->registerFactory(
            className: SocketServerFactory::class,
            factory: $this->makeSocketServerFactory(...),
        );
        $this->registerFactory(
            className: HandlerFactoryInterface::class,
            factory: $this->makeHandlerFactory(...),
        );
        $this->registerFactory(
            className: ServerProtocolFactory::class,
            factory: $this->makeServerProtocolFactory(...),
        );
        $this->registerFactory(
            className: PcntlServerRunner::class,
            factory: $this->makePcntlServerRunner(...),
        );
        $this->registerFactory(
            className: ServerAuthorization::class,
            factory: $this->makeServerAuthorizer(...),
        );
        $this->registerFactory(
            className: ServerProtocolHandlerFactory::class,
            factory: $this->makeServerProtocolHandlerFactory(...),
        );
    }

    private function makeClientProtocolHandler(): ClientProtocolHandler
    {
        return new ClientProtocolHandler(
            options: $this->get(ClientOptions::class),
            clientQueueInstantiator: $this->get(ClientQueueInstantiator::class),
            protocolHandlerFactory: $this->get(ClientProtocolHandlerFactory::class),
        );
    }

    private function makeClientQueueInstantiator(): ClientQueueInstantiator
    {
        return new ClientQueueInstantiator($this->get(SocketPool::class));
    }

    private function makeSocketPool(): SocketPool
    {
        return new SocketPool(
            $this->get(ClientOptions::class)
                ->toArray()
        );
    }

    private function makeClientProtocolHandlerFactory(): ClientProtocolHandlerFactory
    {
        return new ClientProtocolHandlerFactory(
            clientOptions: $this->get(ClientOptions::class),
            queueInstantiator: $this->get(ClientQueueInstantiator::class),
            rootDseLoader: $this->get(RootDseLoader::class),
        );
    }

    private function makeRootDseLoader(): RootDseLoader
    {
        return new RootDseLoader($this->get(LdapClient::class));
    }

    private function makeServerProtocolFactory(): ServerProtocolFactory
    {
        return new ServerProtocolFactory(
            $this->get(HandlerFactory::class),
            $this->get(ServerOptions::class),
        );
    }

    private function makeHandlerFactory(): HandlerFactory
    {
        return new HandlerFactory($this->get(ServerOptions::class));
    }

    private function makePcntlServerRunner(): PcntlServerRunner
    {
        return new PcntlServerRunner(
            $this->get(ServerProtocolFactory::class),
            $this->get(ServerOptions::class)->getLogger(),
        );
    }

    private function makeSocketServerFactory(): SocketServerFactory
    {
        $serverOptions = $this->get(ServerOptions::class);

        return new SocketServerFactory(
            $serverOptions,
            $serverOptions->getLogger(),
        );
    }

    private function makeServerAuthorizer(): ServerAuthorization
    {
        return new ServerAuthorization($this->get(ServerOptions::class));
    }

    private function makeServerProtocolHandlerFactory(): ServerProtocolHandlerFactory
    {
        return new ServerProtocolHandlerFactory(
            $this->get(HandlerFactoryInterface::class),
            new RequestHistory()
        );
    }
}
