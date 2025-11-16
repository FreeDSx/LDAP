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

use FreeDSx\Asn1\Encoder\EncoderInterface;
use FreeDSx\Ldap\Protocol\LdapQueue;
use FreeDSx\Socket\Socket;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class LdapQueueTest extends TestCase
{
    private LdapQueue $subject;

    private Socket&MockObject $mockSocket;

    private EncoderInterface&MockObject $mockEncoder;

    protected function setUp(): void
    {
        $this->mockSocket = $this->createMock(Socket::class);
        $this->mockEncoder = $this->createMock(EncoderInterface::class);

        $this->mockEncoder
            ->expects($this->any())
            ->method('getLastPosition')
            ->willReturn(3);

        $this->mockSocket
            ->expects($this->any())
            ->method('read')
            ->will($this->onConsecutiveCalls(
                'foo',
                false
            ));

        $this->subject = new LdapQueue(
            $this->mockSocket,
            $this->mockEncoder,
        );
    }

    public function test_it_should_get_the_current_id(): void
    {
        self::assertSame(
            0,
            $this->subject->currentId(),
        );
    }

    public function test_it_should_generate_an_id(): void
    {
        self::assertSame(
            1,
            $this->subject->generateId(),
        );
        self::assertSame(
            2,
            $this->subject->generateId(),
        );
    }
}
