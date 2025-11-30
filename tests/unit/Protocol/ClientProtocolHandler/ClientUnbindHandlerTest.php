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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientUnbindHandler;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ClientUnbindHandlerTest extends TestCase
{
    private ClientUnbindHandler $subject;

    private ClientQueue&MockObject $mockQueue;
    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ClientQueue::class);

        $this->subject = new ClientUnbindHandler($this->mockQueue);
    }

    public function test_it_should_send_the_message_and_close_the_queue(): void
    {
        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage');

        $this->mockQueue
            ->expects(self::once())
            ->method('close');

        self::assertNull($this->subject->handleRequest(
            new LdapMessageRequest(1, new UnbindRequest())
        ));
    }
}
