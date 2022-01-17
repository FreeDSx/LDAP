<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Encoder\EncoderInterface;
use FreeDSx\Ldap\Protocol\LdapQueue;
use FreeDSx\Socket\Queue\Asn1MessageQueue;
use FreeDSx\Socket\Socket;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class LdapQueueSpec extends ObjectBehavior
{
    public function let(Socket $socket, EncoderInterface $encoder)
    {
        $socket->read(Argument::any())->willReturn('foo', false);
        $encoder->getLastPosition()->willReturn(3);

        $this->beConstructedWith($socket, $encoder);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(LdapQueue::class);
    }

    public function it_should_extend_the_Asn1MessageQueue()
    {
        $this->shouldBeAnInstanceOf(Asn1MessageQueue::class);
    }

    public function it_should_get_the_current_id()
    {
        $this->currentId()->shouldBeEqualTo(0);
    }

    public function it_should_generate_an_id()
    {
        $this->generateId()->shouldBeEqualTo(1);
        $this->generateId()->shouldBeEqualTo(2);
    }
}
