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
use FreeDSx\Ldap\Exception\ResponseAlreadySentException;
use FreeDSx\Ldap\Exception\SaslNegotiationAbortedException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authenticator;
use FreeDSx\Ldap\Protocol\Bind\BindInterface;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class AuthenticatorTest extends TestCase
{
    private Authenticator $subject;

    private BindInterface&MockObject $authOne;

    private BindInterface&MockObject $authTwo;

    private ServerQueue&MockObject $queue;

    protected function setUp(): void
    {
        $this->authOne = $this->createMock(BindInterface::class);
        $this->authTwo = $this->createMock(BindInterface::class);
        $this->queue = $this->createMock(ServerQueue::class);

        $this->subject = new Authenticator(
            [
                $this->authOne,
                $this->authTwo,
            ],
            $this->queue,
        );
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
            new DeleteRequest('foo'),
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

        $token = BindToken::fromDn(
            'foo',
        );

        $this->authOne
            ->method('supports')
            ->willReturn(true);
        $this->authOne
            ->method('bind')
            ->willReturn($token);

        self::assertSame(
            $token,
            $this->subject->bind($message),
        );
    }

    public function test_a_failed_replacement_bind_is_answered_once_on_its_own_message_id(): void
    {
        $replacement = new LdapMessageRequest(
            2,
            new SimpleBindRequest(
                'foo',
                'wrong',
            ),
        );
        $this->givenTheBindIsReplacedBy(
            $replacement,
            new OperationException(
                'Invalid credentials.',
                ResultCode::INVALID_CREDENTIALS,
            ),
        );

        $this->queue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(
                fn(LdapMessageResponse $response): bool => $response->getMessageId() === 2,
            ));
        self::expectException(ResponseAlreadySentException::class);

        $this->subject->bind($this->initialSaslBind());
    }

    public function test_a_replacement_bind_that_answered_itself_is_not_answered_again(): void
    {
        $replacement = new LdapMessageRequest(
            2,
            new SaslBindRequest('PLAIN'),
        );
        $this->givenTheBindIsReplacedBy(
            $replacement,
            new ResponseAlreadySentException(
                'Invalid credentials.',
                ResultCode::INVALID_CREDENTIALS,
            ),
        );

        $this->queue
            ->expects(self::never())
            ->method('sendMessage');
        self::expectException(ResponseAlreadySentException::class);

        $this->subject->bind($this->initialSaslBind());
    }

    private function initialSaslBind(): LdapMessageRequest
    {
        return new LdapMessageRequest(
            1,
            new SaslBindRequest('CRAM-MD5'),
        );
    }

    private function givenTheBindIsReplacedBy(
        LdapMessageRequest $replacement,
        OperationException $replacementFailure,
    ): void {
        $this->authOne
            ->method('supports')
            ->willReturn(true);
        $this->authOne
            ->method('bind')
            ->willReturnCallback(
                fn(LdapMessageRequest $message): never => throw ($message === $replacement
                    ? $replacementFailure
                    : new SaslNegotiationAbortedException($replacement)),
            );
    }
}
