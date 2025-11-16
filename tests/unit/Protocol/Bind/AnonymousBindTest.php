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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Bind;

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
use FreeDSx\Ldap\Server\Token\AnonToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class AnonymousBindTest extends TestCase
{
    private AnonymousBind $subject;

    private ServerQueue&MockObject $mockQueue;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ServerQueue::class);

        $this->subject = new AnonymousBind($this->mockQueue);
    }

    public function test_it_should_validate_the_version(): void
    {
        self::expectException(OperationException::class);

        $this->mockQueue
            ->expects(self::never())
            ->method('sendMessage');

        $this->subject->bind(
            new LdapMessageRequest(
                1,
                Operations::bindAnonymously()->setVersion(4)
            ),
        );
    }

    public function test_it_should_return_an_anon_token_with_the_supplied_username(): void
    {
        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::equalTo(
                new LdapMessageResponse(
                    1,
                    new BindResponse(new LdapResult(0))
                )
            ))
            ->willReturnSelf();

        self::assertEquals(
            new AnonToken('foo'),
            $this->subject->bind(new LdapMessageRequest(
                1,
                Operations::bindAnonymously('foo')
            )),
        );
    }

    public function test_it_should_only_support_anonymous_binds(): void
    {
        self::assertTrue(
            $this->subject->supports(new LdapMessageRequest(
                1,
                new AnonBindRequest()
            ))
        );
        self::assertFalse(
            $this->subject->supports(new LdapMessageRequest(
                1,
                new SimpleBindRequest(
                    'foo',
                    'bar',
                )
            ))
        );
    }
}
