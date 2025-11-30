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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Queue\MessageWrapper;

use FreeDSx\Ldap\Protocol\Queue\MessageWrapper\SaslMessageWrapper;
use FreeDSx\Sasl\SaslContext;
use FreeDSx\Sasl\Security\SecurityLayerInterface;
use FreeDSx\Socket\Exception\PartialMessageException;
use FreeDSx\Socket\Queue\Buffer;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class SaslMessageWrapperTest extends TestCase
{
    private SaslMessageWrapper $subject;

    private SecurityLayerInterface&MockObject $mockSecurityLayer;

    protected function setUp(): void
    {
        $this->mockSecurityLayer = $this->createMock(SecurityLayerInterface::class);

        $context = new SaslContext();
        $context->setResponse('foo');

        $this->subject = new SaslMessageWrapper(
            $this->mockSecurityLayer,
            $context,
        );
    }

    public function test_it_should_wrap_the_message(): void
    {
        $this->mockSecurityLayer
            ->method('wrap')
            ->with(
                'bar',
                self::isInstanceOf(SaslContext::class),
            )
            ->willReturn('foobar');

        self::assertSame(
            "\x00\x00\x00\x06foobar",
            $this->subject->wrap('bar'),
        );
    }

    public function test_it_should_unwrap_the_message(): void
    {
        $this->mockSecurityLayer
            ->method('unwrap')
            ->with(
                'foobar',
                self::isInstanceOf(SaslContext::class),
            )->willReturn('foobar');

        self::assertEquals(
            new Buffer("foobar", 10),
            $this->subject->unwrap("\x00\x00\x00\x06foobar"),
        );
    }

    public function test_it_should_throw_a_partial_message_exception_when_there_is_not_enough_data_to_unwrap(): void
    {
        $this->mockSecurityLayer
            ->expects(self::never())
            ->method('unwrap');

        self::expectException(PartialMessageException::class);

        $this->subject->unwrap("\x00\x00\x00\x06foo");
    }
}
