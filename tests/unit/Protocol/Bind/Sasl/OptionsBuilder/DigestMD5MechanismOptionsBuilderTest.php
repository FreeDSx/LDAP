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
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\DigestMD5MechanismOptionsBuilder;
use FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor\SaslUsernameExtractorInterface;
use FreeDSx\Ldap\Server\RequestHandler\SaslHandlerInterface;
use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class DigestMD5MechanismOptionsBuilderTest extends TestCase
{
    private SaslHandlerInterface&MockObject $mockHandler;

    private SaslUsernameExtractorInterface&MockObject $mockUsernameExtractor;

    private DigestMD5MechanismOptionsBuilder $subject;

    protected function setUp(): void
    {
        $this->mockHandler = $this->createMock(SaslHandlerInterface::class);
        $this->mockUsernameExtractor = $this->createMock(SaslUsernameExtractorInterface::class);

        $this->subject = new DigestMD5MechanismOptionsBuilder(
            $this->mockHandler,
            $this->mockUsernameExtractor,
        );
    }

    public function test_it_supports_the_digest_md5_mechanism(): void
    {
        self::assertTrue($this->subject->supports(DigestMD5Mechanism::NAME));
    }

    public function test_it_does_not_support_other_mechanisms(): void
    {
        self::assertFalse($this->subject->supports('PLAIN'));
        self::assertFalse($this->subject->supports('CRAM-MD5'));
    }

    public function test_it_returns_empty_options_when_no_bytes_received(): void
    {
        self::assertSame(
            [],
            $this->subject->buildOptions(null, DigestMD5Mechanism::NAME)
        );
    }

    public function test_it_builds_options_with_the_password_when_bytes_are_received(): void
    {
        $this->mockUsernameExtractor
            ->method('extractUsername')
            ->with(DigestMD5Mechanism::NAME, 'client-response')
            ->willReturn('cn=user,dc=foo,dc=bar');

        $this->mockHandler
            ->method('getPassword')
            ->with('cn=user,dc=foo,dc=bar', DigestMD5Mechanism::NAME)
            ->willReturn('12345');

        $options = $this->subject->buildOptions('client-response', DigestMD5Mechanism::NAME);

        self::assertSame(
            ['password' => '12345'],
            $options,
        );
    }

    public function test_it_throws_invalid_credentials_when_password_is_not_found(): void
    {
        $this->mockUsernameExtractor
            ->method('extractUsername')
            ->willReturn('unknown-user');

        $this->mockHandler
            ->method('getPassword')
            ->willReturn(null);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->subject->buildOptions('client-response', DigestMD5Mechanism::NAME);
    }
}
