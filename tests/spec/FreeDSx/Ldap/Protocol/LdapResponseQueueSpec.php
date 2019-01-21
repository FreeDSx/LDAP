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
use FreeDSx\Ldap\Protocol\LdapResponseQueue;
use FreeDSx\Socket\Queue\Asn1MessageQueue;
use FreeDSx\Socket\Socket;
use PhpSpec\ObjectBehavior;

class LdapResponseQueueSpec extends ObjectBehavior
{
    function let(Socket $socket, EncoderInterface $encoder)
    {
        $this->beConstructedWith($socket, $encoder);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(LdapResponseQueue::class);
    }

    function it_should_extend_the_Asn1MessageQueue()
    {
        $this->shouldBeAnInstanceOf(Asn1MessageQueue::class);
    }
}
