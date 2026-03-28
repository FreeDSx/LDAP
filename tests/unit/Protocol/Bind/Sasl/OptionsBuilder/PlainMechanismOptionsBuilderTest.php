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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder;

use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\PlainMechanismOptionsBuilder;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Sasl\Mechanism\PlainMechanism;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class PlainMechanismOptionsBuilderTest extends TestCase
{
    private RequestHandlerInterface&MockObject $mockDispatcher;

    private PlainMechanismOptionsBuilder $subject;

    protected function setUp(): void
    {
        $this->mockDispatcher = $this->createMock(RequestHandlerInterface::class);
        $this->subject = new PlainMechanismOptionsBuilder($this->mockDispatcher);
    }

    public function test_it_supports_the_plain_mechanism(): void
    {
        self::assertTrue($this->subject->supports(PlainMechanism::NAME));
    }

    public function test_it_does_not_support_other_mechanisms(): void
    {
        self::assertFalse($this->subject->supports('CRAM-MD5'));
    }

    public function test_it_builds_options_with_a_validate_callable(): void
    {
        $options = $this->subject->buildOptions(null, PlainMechanism::NAME);

        self::assertArrayHasKey(
            'validate',
            $options,
        );
        self::assertIsCallable($options['validate']);
    }

    public function test_the_validate_callable_delegates_to_dispatcher_bind(): void
    {
        $this->mockDispatcher
            ->expects(self::once())
            ->method('bind')
            ->with('cn=user,dc=foo,dc=bar', '12345')
            ->willReturn(true);

        $options = $this->subject->buildOptions(null, PlainMechanism::NAME);
        $validate = $options['validate'];
        assert(is_callable($validate));
        $result = $validate('authzid', 'cn=user,dc=foo,dc=bar', '12345');

        self::assertTrue($result);
    }

    public function test_the_validate_callable_returns_false_when_bind_fails(): void
    {
        $this->mockDispatcher
            ->method('bind')
            ->willReturn(false);

        $options = $this->subject->buildOptions(null, PlainMechanism::NAME);
        $validate = $options['validate'];
        assert(is_callable($validate));
        $result = $validate(null, 'user', 'wrong');

        self::assertFalse($result);
    }

    public function test_it_builds_the_same_options_regardless_of_received_bytes(): void
    {
        $optionsWithNull = $this->subject->buildOptions(null, PlainMechanism::NAME);
        $optionsWithBytes = $this->subject->buildOptions('some-bytes', PlainMechanism::NAME);

        self::assertArrayHasKey('validate', $optionsWithNull);
        self::assertArrayHasKey('validate', $optionsWithBytes);
    }
}
