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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerUnbindHandler;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerUnbindHandlerTest extends TestCase
{
    private ServerQueue&MockObject $mockQueue;

    private ServerUnbindHandler $subject;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ServerQueue::class);

        $this->subject = new ServerUnbindHandler($this->mockQueue);
    }

    public function test_it_should_handle_an_unbind_request(): void
    {
        $this->mockQueue
            ->expects($this->once())
            ->method('close');
        $this->mockQueue
            ->expects($this->never())
            ->method('sendMessage');

        $this->subject->handleRequest(
            new LdapMessageRequest(1, new UnbindRequest()),
            $this->createMock(TokenInterface::class),
        );
    }
}
