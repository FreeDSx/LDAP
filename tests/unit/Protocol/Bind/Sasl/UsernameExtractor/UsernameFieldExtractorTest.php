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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor\UsernameFieldExtractor;
use FreeDSx\Sasl\Encoder\EncoderInterface;
use FreeDSx\Sasl\Mechanism\CramMD5Mechanism;
use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;
use FreeDSx\Sasl\Message;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class UsernameFieldExtractorTest extends TestCase
{
    private EncoderInterface&MockObject $mockEncoder;

    private UsernameFieldExtractor $subject;

    protected function setUp(): void
    {
        $this->mockEncoder = $this->createMock(EncoderInterface::class);

        $this->subject = new UsernameFieldExtractor([
            CramMD5Mechanism::NAME => $this->mockEncoder,
        ]);
    }

    public function test_it_supports_mechanisms_that_have_a_registered_encoder(): void
    {
        self::assertTrue($this->subject->supports(CramMD5Mechanism::NAME));
    }

    public function test_it_does_not_support_mechanisms_without_a_registered_encoder(): void
    {
        self::assertFalse($this->subject->supports('PLAIN'));
    }

    public function test_it_defaults_to_supporting_cram_md5_and_digest_md5(): void
    {
        $subject = new UsernameFieldExtractor();

        self::assertTrue($subject->supports(CramMD5Mechanism::NAME));
        self::assertTrue($subject->supports(DigestMD5Mechanism::NAME));
    }

    public function test_it_extracts_the_username_field_from_decoded_credentials(): void
    {
        $credentials = 'some-credential-bytes';

        $this->mockEncoder
            ->expects(self::once())
            ->method('decode')
            ->willReturn(new Message(['username' => 'cn=user,dc=foo,dc=bar']));

        self::assertSame(
            'cn=user,dc=foo,dc=bar',
            $this->subject->extractUsername(CramMD5Mechanism::NAME, $credentials),
        );
    }

    public function test_it_decodes_credentials_in_server_mode(): void
    {
        $this->mockEncoder
            ->expects(self::once())
            ->method('decode')
            ->with(
                self::anything(),
                self::callback(fn (SaslContext $ctx): bool => $ctx->isServerMode()),
            )
            ->willReturn(new Message(['username' => 'user']));

        $this->subject->extractUsername(CramMD5Mechanism::NAME, 'bytes');
    }

    public function test_it_throws_a_protocol_error_when_the_username_field_is_missing(): void
    {
        $this->mockEncoder
            ->method('decode')
            ->willReturn(new Message([]));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $this->subject->extractUsername(
            CramMD5Mechanism::NAME,
            'bytes'
        );
    }
}
