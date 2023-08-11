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

namespace spec\FreeDSx\Ldap\Protocol\Bind;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\Bind\AnonymousBind;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\AnonToken;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class AnonymousBindSpec extends ObjectBehavior
{
    public function let(ServerQueue $queue): void
    {
        $this->beConstructedWith($queue);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(AnonymousBind::class);
    }

    public function it_should_validate_the_version(ServerQueue $queue, RequestHandlerInterface $dispatcher): void
    {
        $bind = new LdapMessageRequest(
            1,
            Operations::bindAnonymously()->setVersion(4)
        );

        $queue->sendMessage(Argument::any())->shouldNotBeCalled();

        $this->shouldThrow(OperationException::class)->during(
            'bind',
            [$bind, $dispatcher, $queue]
        );
    }

    public function it_should_return_an_anon_token_with_the_supplied_username(ServerQueue $queue, RequestHandlerInterface $dispatcher): void
    {
        $bind = new LdapMessageRequest(
            1,
            Operations::bindAnonymously('foo')
        );

        $queue->sendMessage(new LdapMessageResponse(1, new BindResponse(
            new LdapResult(0)
        )))->shouldBeCalled()->willReturn($queue);

        $this->bind($bind)->shouldBeLike(
            new AnonToken('foo')
        );
    }

    public function it_should_only_support_anonymous_binds(): void
    {
        $this->supports(new LdapMessageRequest(
            1,
            new AnonBindRequest()
        ))->shouldBe(true);
        $this->supports(new LdapMessageRequest(
            1,
            new SimpleBindRequest(
                'foo',
                'bar',
            )
        ))->shouldBe(false);
    }
}
