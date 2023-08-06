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

namespace spec\FreeDSx\Ldap;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ClientQueueInstantiator;
use FreeDSx\Ldap\Protocol\RootDseLoader;
use FreeDSx\Socket\SocketPool;
use PhpSpec\ObjectBehavior;

class ContainerSpec extends ObjectBehavior
{
    public function let(): void
    {
        $client = new LdapClient();

        $this->beConstructedWith([
            LdapClient::class => $client,
            ClientOptions::class => $client->getOptions(),
        ]);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(Container::class);
    }

    public function it_should_get_the_client(LdapClient $client): void
    {
        $this->get(LdapClient::class)
            ->shouldBeAnInstanceOf(LdapClient::class);
    }

    public function it_should_make_the_client_protocol_handler(): void
    {
        $this->get(ClientProtocolHandler::class)
            ->shouldBeAnInstanceOf(ClientProtocolHandler::class);
    }

    public function it_should_make_the_ClientQueueInstantiator(): void
    {
        $this->get(ClientQueueInstantiator::class)
            ->shouldBeAnInstanceOf(ClientQueueInstantiator::class);
    }

    public function it_shoulld_make_the_ClientProtocolHandlerFactory(): void
    {
        $this->get(ClientProtocolHandlerFactory::class)
            ->shouldBeAnInstanceOf(ClientProtocolHandlerFactory::class);
    }

    public function it_should_make_the_SocketPool(): void
    {
        $this->get(SocketPool::class)
            ->shouldBeAnInstanceOf(SocketPool::class);
    }

    public function it_should_make_the_RootDseLoader(): void
    {
        $this->get(RootDseLoader::class)
            ->shouldBeAnInstanceOf(RootDseLoader::class);
    }
}
