<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\Queue\MessageWrapper;

use FreeDSx\Ldap\Protocol\Queue\MessageWrapper\SaslMessageWrapper;
use FreeDSx\Sasl\SaslContext;
use FreeDSx\Sasl\Security\SecurityLayerInterface;
use FreeDSx\Socket\Exception\PartialMessageException;
use FreeDSx\Socket\Queue\Buffer;
use FreeDSx\Socket\Queue\Message;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class SaslMessageWrapperSpec extends ObjectBehavior
{
    function let(SecurityLayerInterface $securityLayer)
    {
        $context = new SaslContext();
        $context->setResponse('foo');
        $this->beConstructedWith($securityLayer, $context);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SaslMessageWrapper::class);
    }

    function it_should_wrap_the_message(SecurityLayerInterface $securityLayer)
    {
        $securityLayer->wrap('bar', Argument::type(SaslContext::class))
            ->shouldBeCalled()
            ->willReturn('foobar');

        $this->wrap('bar')->shouldBeEqualTo("\x00\x00\x00\x06foobar");
    }

    function it_should_unwrap_the_message(SecurityLayerInterface $securityLayer)
    {
        $securityLayer->unwrap('foobar', Argument::type(SaslContext::class))
            ->shouldBeCalled()
            ->willReturn('foobar');

        $this->unwrap("\x00\x00\x00\x06foobar")->shouldBeLike(new Buffer("foobar", 10));
    }

    function it_should_throw_a_partial_message_exception_when_there_is_not_enough_data_to_unwrap(SecurityLayerInterface $securityLayer)
    {
        $securityLayer->unwrap(Argument::any(), Argument::any())->shouldNotBeCalled();

        $this->shouldThrow(PartialMessageException::class)->during('unwrap', ["\x00\x00\x00\x06foo"]);
    }
}
