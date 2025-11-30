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

namespace Tests\Unit\FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Protocol\Authenticator;
use FreeDSx\Ldap\Protocol\Bind\BindInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class AuthenticatorTest extends TestCase
{
    private Authenticator $subject;

    private BindInterface&MockObject $authOne;

    private BindInterface&MockObject $authTwo;

    protected function setUp(): void
    {
        $this->authOne = $this->createMock(BindInterface::class);
        $this->authTwo = $this->createMock(BindInterface::class);

        $this->subject = new Authenticator([
            $this->authOne,
            $this->authTwo,
        ]);
    }

    public function test_it_should_throw_an_exception_on_an_unknown_bind_type(): void
    {
        self::expectException(OperationException::class);

        $this->authOne
            ->method('supports')
            ->willReturn(false);
        $this->authTwo
            ->method('supports')
            ->willReturn(false);

        $this->subject->bind(new LdapMessageRequest(
            1,
            new DeleteRequest('foo')
        ));
    }

    public function test_it_should_return_the_token(): void
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

        $this->authOne
            ->method('supports')
            ->willReturn(true);
        $this->authOne
            ->method('bind')
            ->willReturn($token);

        self::assertSame(
            $token,
            $this->subject->bind($message)
        );
    }
}
