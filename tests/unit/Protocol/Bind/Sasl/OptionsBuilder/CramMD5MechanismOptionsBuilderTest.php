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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\CramMD5MechanismOptionsBuilder;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Sasl\Mechanism\CramMD5Mechanism;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class CramMD5MechanismOptionsBuilderTest extends TestCase
{
    private PasswordAuthenticatableInterface&MockObject $mockHandler;

    private CramMD5MechanismOptionsBuilder $subject;

    protected function setUp(): void
    {
        $this->mockHandler = $this->createMock(PasswordAuthenticatableInterface::class);
        $this->subject = new CramMD5MechanismOptionsBuilder($this->mockHandler);
    }

    public function test_it_supports_the_cram_md5_mechanism(): void
    {
        self::assertTrue($this->subject->supports(CramMD5Mechanism::NAME));
    }

    public function test_it_does_not_support_other_mechanisms(): void
    {
        self::assertFalse($this->subject->supports('PLAIN'));
        self::assertFalse($this->subject->supports('DIGEST-MD5'));
    }

    public function test_it_returns_empty_options_when_no_bytes_received(): void
    {
        self::assertSame(
            [],
            $this->subject->buildOptions(null, CramMD5Mechanism::NAME)
        );
    }

    public function test_it_builds_options_with_a_password_callable_when_bytes_are_received(): void
    {
        $options = $this->subject->buildOptions(
            'some-client-response',
            CramMD5Mechanism::NAME,
        );

        self::assertArrayHasKey(
            'password',
            $options
        );
        self::assertIsCallable($options['password']);
    }

    public function test_the_password_callable_returns_an_hmac_of_the_challenge(): void
    {
        $this->mockHandler
            ->method('getPassword')
            ->with('cn=user,dc=foo,dc=bar', CramMD5Mechanism::NAME)
            ->willReturn('12345');

        $options = $this->subject->buildOptions('some-bytes', CramMD5Mechanism::NAME);
        $password = $options['password'];
        assert(is_callable($password));
        // The challenge passed to the callable is the encoded challenge string exactly as the
        // client received it (e.g. "<nonce>"), per RFC 2195.
        $challenge = '<challenge@example.com>';
        $result = $password('cn=user,dc=foo,dc=bar', $challenge);

        self::assertSame(
            hash_hmac('md5', '<challenge@example.com>', '12345'),
            $result
        );
    }

    public function test_the_password_callable_throws_invalid_credentials_when_user_not_found(): void
    {
        $this->mockHandler
            ->method('getPassword')
            ->willReturn(null);

        $options = $this->subject->buildOptions(
            'some-bytes',
            CramMD5Mechanism::NAME
        );
        $password = $options['password'];
        assert(is_callable($password));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $password('unknown-user', 'challenge');
    }
}
