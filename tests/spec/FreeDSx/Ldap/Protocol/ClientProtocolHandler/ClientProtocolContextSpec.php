<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\ClientProtocolHandler;

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
    function let(ClientQueue $queue, ClientProtocolHandler $protocolHandler)
    {
        $this->beConstructedWith(new DeleteRequest('foo'), [], $protocolHandler, $queue, ['foo']);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ClientProtocolContext::class);
    }

    public function it_should_get_the_message_to_send(ClientQueue $queue)
    {
        $queue->generateId()->shouldBeCalled()->willReturn(1);

        $this->messageToSend()->shouldBeLike(new LdapMessageRequest(1, new DeleteRequest('foo')));
    }

    public function it_should_fetch_the_root_dse(ClientProtocolHandler $protocolHandler)
    {
        $entry = new Entry(new Dn(''));
        $protocolHandler->fetchRootDse(false)->shouldBeCalled()->willReturn($entry);

        $this->getRootDse()->shouldBeEqualTo($entry);
    }

    public function it_should_force_fetch_the_root_dse(ClientProtocolHandler $protocolHandler)
    {
        $entry = new Entry(new Dn(''));
        $protocolHandler->fetchRootDse(true)->shouldBeCalled()->willReturn($entry);

        $this->getRootDse(true)->shouldBeEqualTo($entry);
    }

    public function it_should_get_the_controls()
    {
        $this->getControls()->shouldBeEqualTo([]);
    }

    public function it_should_get_the_options()
    {
        $this->getOptions()->shouldBeEqualTo(['foo']);
    }

    public function it_should_get_the_queue(ClientQueue $queue)
    {
        $this->getQueue()->shouldBeEqualTo($queue);
    }
}
