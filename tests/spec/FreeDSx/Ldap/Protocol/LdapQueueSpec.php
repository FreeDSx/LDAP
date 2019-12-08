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

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Encoder\EncoderInterface;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\LdapQueue;
use FreeDSx\Ldap\Protocol\Queue\MessageWrapperInterface;
use FreeDSx\Socket\Queue\Asn1MessageQueue;
use FreeDSx\Socket\Queue\Message;
use FreeDSx\Socket\Socket;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class LdapQueueSpec extends ObjectBehavior
{
    function let(Socket $socket, EncoderInterface $encoder)
    {
        $socket->read(Argument::any())->willReturn('foo', false);
        $encoder->getLastPosition()->willReturn(3);

        $this->beConstructedWith($socket, $encoder);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(LdapQueue::class);
    }

    function it_should_extend_the_Asn1MessageQueue()
    {
        $this->shouldBeAnInstanceOf(Asn1MessageQueue::class);
    }

    function it_should_get_the_current_id()
    {
        $this->currentId()->shouldBeEqualTo(0);
    }

    function it_should_generate_an_id()
    {
        $this->generateId()->shouldBeEqualTo(1);
        $this->generateId()->shouldBeEqualTo(2);
    }
}
