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

use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientUnbindHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use PhpSpec\ObjectBehavior;

class ClientUnbindHandlerSpec extends ObjectBehavior
{
    public function let(ClientQueue $queue): void
    {
        $this->beConstructedWith($queue);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ClientUnbindHandler::class);
    }

    public function it_should_implement_RequestHandlerInterface(): void
    {
        $this->shouldBeAnInstanceOf(RequestHandlerInterface::class);
    }

    public function it_should_send_the_message_and_close_the_queue(ClientQueue $queue): void
    {
        $unbind = new LdapMessageRequest(1, new UnbindRequest());
        $queue->sendMessage($unbind)->shouldBeCalledOnce();
        $queue->close()->shouldBeCalledOnce();

        $this->handleRequest($unbind)
            ->shouldBeNull();
    }
}
