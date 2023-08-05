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
use FreeDSx\Ldap\Protocol\Queue\ClientQueueInstantiator;
use FreeDSx\Ldap\Server\ServerRunner\PcntlServerRunner;
use FreeDSx\Socket\SocketPool;

class Container
{
    private ClientOptions $clientOptions;

    private ServerOptions $serverOptions;

    /**
     * @var array<class-string, callable>
     */
    private array $instanceFactory = [];

    /**
     * @var array<class-string, object>
     */
    private array $instances = [];

    public function __construct(
        ?ClientOptions $clientOptions = null,
        ?ServerOptions $serverOptions = null,
    ) {
        if ($clientOptions) {
            $this->clientOptions = $clientOptions;
            $this->registerClientClasses();
        }
        if ($serverOptions) {
            $this->serverOptions = $serverOptions;
            $this->registerServerClasses();
        }
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

        $this->instances[$className] = ($this->instanceFactory[$className])();

        return $this->instances[$className];
    }

    public function hasInstance(string $className): bool
    {
        return isset($this->instances[$className]);
    }

    private function registerClientClasses(): void
    {
        $this->instanceFactory[ClientProtocolHandler::class] = $this->makeClientProtocolHandler(...);
        $this->instanceFactory[SocketPool::class] = $this->makeSocketPool(...);
        $this->instanceFactory[ClientProtocolHandlerFactory::class] = $this->makeClientProtocolHandlerFactory(...);
        $this->instanceFactory[ClientQueueInstantiator::class] = $this->makeClientQueueInstantiator(...);
    }

    private function registerServerClasses(): void
    {
        $this->instanceFactory[PcntlServerRunner::class] = $this->makePcntlServerRunner(...);
    }

    private function makeClientProtocolHandler(): ClientProtocolHandler
    {
        return new ClientProtocolHandler(
            options: $this->clientOptions,
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
        return new SocketPool($this->clientOptions->toArray());
    }

    private function makeClientProtocolHandlerFactory(): ClientProtocolHandlerFactory
    {
        return new ClientProtocolHandlerFactory($this->clientOptions);
    }

    private function makePcntlServerRunner(): PcntlServerRunner
    {
        return new PcntlServerRunner($this->serverOptions);
    }
}
