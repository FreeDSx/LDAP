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

namespace spec\FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Protocol\Authenticator;
use FreeDSx\Ldap\Protocol\Bind\BindInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\Token\BindToken;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class AuthenticatorSpec extends ObjectBehavior
{
    public function let(
        BindInterface $authOne,
        BindInterface $authTwo,
    ): void {
        $this->beConstructedWith([
            $authOne,
            $authTwo,
        ]);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(Authenticator::class);
    }

    public function it_should_throw_an_exception_on_an_unknown_bind_type(
        BindInterface $authOne,
        BindInterface $authTwo,
    ): void {
        $authOne
            ->supports(Argument::any())
            ->willReturn(false);
        $authTwo
            ->supports(Argument::any())
            ->willReturn(false);

        $this->shouldThrow(OperationException::class)
            ->during(
                'bind',
                [new LdapMessageRequest(1, new DeleteRequest('foo'))]
            );
    }

    public function it_should_return_the_token(BindInterface $authOne): void
    {
        $bindReq = new SimpleBindRequest(
            'foo',
            'bar',
        );
        $message = new LdapMessageRequest(
            1,
            $bindReq,
        );

        $token = new BindToken(
            'foo',
            'bar',
        );

        $authOne
            ->supports($message)
            ->willReturn(true);
        $authOne
            ->bind($message)
            ->willReturn($token);

        $this->bind($message)
            ->shouldBe($token);
    }
}
