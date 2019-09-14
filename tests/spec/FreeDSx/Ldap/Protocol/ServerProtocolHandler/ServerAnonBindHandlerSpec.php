<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerAnonBindHandler;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\AnonToken;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ServerAnonBindHandlerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ServerAnonBindHandler::class);
    }

    function it_should_validate_the_version(ServerQueue $queue, RequestHandlerInterface $dispatcher)
    {
        $bind = new LdapMessageRequest(
            1,
            Operations::bindAnonymously()->setVersion(4)
        );

        $queue->sendMessage(Argument::any())->shouldNotBeCalled();

        $this->shouldThrow(OperationException::class)->during(
            'handleBind',
            [$bind, $dispatcher, $queue, []]
        );
    }

    function it_should_return_an_anon_token_with_the_supplied_username(ServerQueue $queue, RequestHandlerInterface $dispatcher)
    {
        $bind = new LdapMessageRequest(
            1,
            Operations::bindAnonymously('foo')
        );

        $queue->sendMessage(new LdapMessageResponse(1, new BindResponse(
            new LdapResult(0)
        )))->shouldBeCalled()->willReturn($queue);

        $this->handleBind($bind, $dispatcher, $queue, [])->shouldBeLike(
            new AnonToken('foo')
        );
    }
}
