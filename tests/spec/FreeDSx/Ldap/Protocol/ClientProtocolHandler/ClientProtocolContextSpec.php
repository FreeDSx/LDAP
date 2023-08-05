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

namespace spec\FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientProtocolContext;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use PhpSpec\ObjectBehavior;

class ClientProtocolContextSpec extends ObjectBehavior
{
    public function let(ClientQueue $queue, ClientProtocolHandler $protocolHandler): void
    {
        $this->beConstructedWith(
            new DeleteRequest('foo'),
            [],
            $protocolHandler,
            $queue,
            new ClientOptions()
        );
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ClientProtocolContext::class);
    }

    public function it_should_get_the_message_to_send(ClientQueue $queue): void
    {
        $queue->generateId()->shouldBeCalled()->willReturn(1);

        $this->messageToSend()->shouldBeLike(new LdapMessageRequest(1, new DeleteRequest('foo')));
    }

    public function it_should_fetch_the_root_dse(ClientProtocolHandler $protocolHandler): void
    {
        $entry = new Entry(new Dn(''));
        $protocolHandler->fetchRootDse(false)->shouldBeCalled()->willReturn($entry);

        $this->getRootDse()->shouldBeEqualTo($entry);
    }

    public function it_should_force_fetch_the_root_dse(ClientProtocolHandler $protocolHandler): void
    {
        $entry = new Entry(new Dn(''));
        $protocolHandler->fetchRootDse(true)->shouldBeCalled()->willReturn($entry);

        $this->getRootDse(true)->shouldBeEqualTo($entry);
    }

    public function it_should_get_the_controls(): void
    {
        $this->getControls()->shouldBeEqualTo([]);
    }
}
