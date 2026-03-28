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
use FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor\ScramUsernameExtractor;
use FreeDSx\Sasl\Mechanism\ScramMechanism;
use PHPUnit\Framework\TestCase;

final class ScramUsernameExtractorTest extends TestCase
{
    private ScramUsernameExtractor $subject;

    protected function setUp(): void
    {
        $this->subject = new ScramUsernameExtractor();
    }

    public function test_it_supports_all_scram_variants(): void
    {
        foreach (ScramMechanism::VARIANTS as $variant) {
            self::assertTrue(
                $this->subject->supports($variant),
                "Expected support for $variant"
            );
        }
    }

    public function test_it_does_not_support_non_scram_mechanisms(): void
    {
        self::assertFalse($this->subject->supports('PLAIN'));
        self::assertFalse($this->subject->supports('CRAM-MD5'));
        self::assertFalse($this->subject->supports('DIGEST-MD5'));
    }

    public function test_it_extracts_username_from_standard_client_first(): void
    {
        // n,, GS2 header (no channel binding)
        self::assertSame(
            'testuser',
            $this->subject->extractUsername(
                ScramMechanism::SHA256,
                'n,,n=testuser,r=clientnonce',
            )
        );
    }

    public function test_it_extracts_username_from_channel_binding_client_first(): void
    {
        // p=tls-unique,, GS2 header
        self::assertSame(
            'testuser',
            $this->subject->extractUsername(
                ScramMechanism::SHA256_PLUS,
                'p=tls-unique,,n=testuser,r=clientnonce'
            ),
        );
    }

    public function test_it_decodes_rfc5802_encoded_comma_in_username(): void
    {
        // ',' is encoded as '=2C'
        self::assertSame(
            'user,name',
            $this->subject->extractUsername(
                ScramMechanism::SHA256,
                'n,,n=user=2Cname,r=nonce',
            )
        );
    }

    public function test_it_decodes_rfc5802_encoded_equals_in_username(): void
    {
        // '=' is encoded as '=3D'
        self::assertSame(
            'user=name',
            $this->subject->extractUsername(
                ScramMechanism::SHA256,
                'n,,n=user=3Dname,r=nonce'
            )
        );
    }

    public function test_it_throws_protocol_error_when_username_field_is_missing(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        // Malformed message with no n= field
        $this->subject->extractUsername(
            ScramMechanism::SHA256,
            'n,,r=nonce'
        );
    }

    public function test_it_extracts_username_when_credentials_have_no_gs2_header(): void
    {
        // No ',,' separator — the whole string is treated as the bare client-first-message.
        self::assertSame(
            'testuser',
            $this->subject->extractUsername(
                ScramMechanism::SHA256,
                'n=testuser,r=nonce',
            ),
        );
    }
}
