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

namespace FreeDSx\Ldap\Container\Provider;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ClientQueueInstantiator;
use FreeDSx\Ldap\Protocol\RootDseLoader;
use FreeDSx\Socket\SocketOptions;
use FreeDSx\Socket\SocketPool;
use FreeDSx\Socket\SocketPoolOptions;
use FreeDSx\Socket\Transport;

/**
 * Registers the client-side protocol and socket services.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ClientContainerProvider implements ContainerProviderInterface
{
    public function factories(): array
    {
        return [
            ClientProtocolHandler::class => $this->makeClientProtocolHandler(...),
            SocketPool::class => $this->makeSocketPool(...),
            ClientProtocolHandlerFactory::class => $this->makeClientProtocolHandlerFactory(...),
            ClientQueueInstantiator::class => $this->makeClientQueueInstantiator(...),
            RootDseLoader::class => $this->makeRootDseLoader(...),
        ];
    }

    private function makeClientProtocolHandler(Container $container): ClientProtocolHandler
    {
        return new ClientProtocolHandler(
            options: $container->get(ClientOptions::class),
            clientQueueInstantiator: $container->get(ClientQueueInstantiator::class),
            protocolHandlerFactory: $container->get(ClientProtocolHandlerFactory::class),
        );
    }

    private function makeClientQueueInstantiator(Container $container): ClientQueueInstantiator
    {
        return new ClientQueueInstantiator($container->get(SocketPool::class));
    }

    private function makeSocketPool(Container $container): SocketPool
    {
        $clientOptions = $container->get(ClientOptions::class);
        $socketOptions = (new SocketOptions())
            ->setTransport(Transport::from($clientOptions->getTransport()))
            ->setPort($clientOptions->getPort())
            ->setUseSsl($clientOptions->isUseSsl())
            ->setSslValidateCert($clientOptions->isSslValidateCert())
            ->setSslAllowSelfSigned($clientOptions->isSslAllowSelfSigned())
            ->setSslCaCert($clientOptions->getSslCaCert())
            ->setSslCert($clientOptions->getSslCert())
            ->setSslCertKey($clientOptions->getSslCertKey())
            ->setSslPeerName($clientOptions->getSslPeerName())
            ->setTimeoutConnect($clientOptions->getTimeoutConnect())
            ->setTimeoutRead($clientOptions->getTimeoutRead());

        $poolOptions = (new SocketPoolOptions($socketOptions))
            ->setServers($clientOptions->getServers());

        return new SocketPool($poolOptions);
    }

    private function makeClientProtocolHandlerFactory(Container $container): ClientProtocolHandlerFactory
    {
        return new ClientProtocolHandlerFactory(
            clientOptions: $container->get(ClientOptions::class),
            queueInstantiator: $container->get(ClientQueueInstantiator::class),
            rootDseLoader: $container->get(RootDseLoader::class),
        );
    }

    private function makeRootDseLoader(Container $container): RootDseLoader
    {
        return new RootDseLoader($container->get(LdapClient::class));
    }
}
