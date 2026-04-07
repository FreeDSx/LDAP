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
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\ScramMechanismOptionsBuilder;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Sasl\Mechanism\ScramMechanism;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ScramMechanismOptionsBuilderTest extends TestCase
{
    private PasswordAuthenticatableInterface&MockObject $mockHandler;

    private ScramMechanismOptionsBuilder $subject;

    protected function setUp(): void
    {
        $this->mockHandler = $this->createMock(PasswordAuthenticatableInterface::class);
        $this->subject = new ScramMechanismOptionsBuilder($this->mockHandler);
    }

    public function test_it_supports_all_scram_variants(): void
    {
        foreach (ScramMechanism::VARIANTS as $variant) {
            self::assertTrue($this->subject->supports($variant), "Expected support for $variant");
        }
    }

    public function test_it_does_not_support_other_mechanisms(): void
    {
        self::assertFalse($this->subject->supports('PLAIN'));
        self::assertFalse($this->subject->supports('CRAM-MD5'));
        self::assertFalse($this->subject->supports('DIGEST-MD5'));
    }

    public function test_it_returns_empty_options_when_no_bytes_received(): void
    {
        self::assertSame([], $this->subject->buildOptions(null, ScramMechanism::SHA256));
    }

    public function test_it_returns_empty_options_for_client_first_message(): void
    {
        // Client-first: GS2 header + username + cnonce, no proof field.
        $clientFirst = 'n,,n=testuser,r=clientnonce123';

        self::assertSame([], $this->subject->buildOptions($clientFirst, ScramMechanism::SHA256));
    }

    public function test_it_extracts_username_from_client_first_and_provides_password_on_client_final(): void
    {
        $this->mockHandler
            ->expects(self::once())
            ->method('getPassword')
            ->with('testuser', ScramMechanism::SHA256)
            ->willReturn('secret');

        $this->subject->buildOptions('n,,n=testuser,r=clientnonce123', ScramMechanism::SHA256);
        $options = $this->subject->buildOptions('c=biws,r=clientnonce123servernonce,p=dGVzdA==', ScramMechanism::SHA256);

        self::assertArrayHasKey('password', $options);
        self::assertSame('secret', $options['password']);
    }

    public function test_it_passes_the_mechanism_name_to_the_handler(): void
    {
        $this->mockHandler
            ->expects(self::once())
            ->method('getPassword')
            ->with('user', ScramMechanism::SHA512)
            ->willReturn('pw');

        $this->subject->buildOptions('n,,n=user,r=nonce', ScramMechanism::SHA512);
        $this->subject->buildOptions('c=biws,r=fullnonce,p=proof==', ScramMechanism::SHA512);
    }

    public function test_it_throws_invalid_credentials_when_user_not_found(): void
    {
        $this->mockHandler
            ->method('getPassword')
            ->willReturn(null);

        $this->subject->buildOptions('n,,n=unknown,r=nonce', ScramMechanism::SHA256);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->subject->buildOptions('c=biws,r=fullnonce,p=someproof==', ScramMechanism::SHA256);
    }

    public function test_it_throws_protocol_error_when_client_final_received_before_client_first(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        // Client-final arrives without a prior client-first.
        $this->subject->buildOptions('c=biws,r=fullnonce,p=proof==', ScramMechanism::SHA256);
    }

    public function test_it_decodes_rfc5802_encoded_username(): void
    {
        $this->mockHandler
            ->expects(self::once())
            ->method('getPassword')
            ->with('user,name=test', ScramMechanism::SHA256)
            ->willReturn('pw');

        // ',' encoded as '=2C', '=' encoded as '=3D'
        $this->subject->buildOptions('n,,n=user=2Cname=3Dtest,r=nonce', ScramMechanism::SHA256);
        $this->subject->buildOptions('c=biws,r=fullnonce,p=proof==', ScramMechanism::SHA256);
    }

    public function test_it_handles_channel_binding_gs2_header(): void
    {
        $this->mockHandler
            ->method('getPassword')
            ->willReturn('pw');

        // 'p=tls-unique,,' GS2 header for channel-binding variants
        $this->subject->buildOptions('p=tls-unique,,n=user,r=nonce', ScramMechanism::SHA256_PLUS);
        $options = $this->subject->buildOptions('c=cD10bHMtdW5pcXVlLCwx,r=fullnonce,p=proof==', ScramMechanism::SHA256_PLUS);

        self::assertArrayHasKey('password', $options);
    }

    public function test_it_parses_username_from_client_first_without_gs2_header(): void
    {
        $this->mockHandler
            ->expects(self::once())
            ->method('getPassword')
            ->with('user', ScramMechanism::SHA256)
            ->willReturn('pw');

        // No ',,' separator — treat the whole string as the bare client-first-message.
        $this->subject->buildOptions('n=user,r=nonce', ScramMechanism::SHA256);
        $options = $this->subject->buildOptions('c=biws,r=fullnonce,p=proof==', ScramMechanism::SHA256);

        self::assertArrayHasKey('password', $options);
    }

    public function test_it_throws_protocol_error_when_client_first_has_no_username_field(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        // After stripping the GS2 header the bare message contains no 'n=' field.
        $this->subject->buildOptions('n,,r=nonce-only', ScramMechanism::SHA256);
    }
}
