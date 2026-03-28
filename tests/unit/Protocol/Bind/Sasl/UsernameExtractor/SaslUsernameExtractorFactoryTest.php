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

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor\PlainUsernameExtractor;
use FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor\SaslUsernameExtractorFactory;
use FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor\ScramUsernameExtractor;
use FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor\UsernameFieldExtractor;
use PHPUnit\Framework\TestCase;

final class SaslUsernameExtractorFactoryTest extends TestCase
{
    private SaslUsernameExtractorFactory $subject;

    protected function setUp(): void
    {
        $this->subject = new SaslUsernameExtractorFactory();
    }

    public function test_make_plain_returns_plain_extractor(): void
    {
        self::assertInstanceOf(
            PlainUsernameExtractor::class,
            $this->subject->make('PLAIN')
        );
    }

    public function test_make_scram_sha256_returns_scram_extractor(): void
    {
        self::assertInstanceOf(
            ScramUsernameExtractor::class,
            $this->subject->make('SCRAM-SHA-256')
        );
    }

    public function test_make_cram_md5_returns_username_field_extractor(): void
    {
        self::assertInstanceOf(
            UsernameFieldExtractor::class,
            $this->subject->make('CRAM-MD5')
        );
    }

    public function test_make_digest_md5_returns_username_field_extractor(): void
    {
        self::assertInstanceOf(
            UsernameFieldExtractor::class,
            $this->subject->make('DIGEST-MD5')
        );
    }

    public function test_make_unknown_mechanism_throws(): void
    {
        self::expectException(RuntimeException::class);

        $this->subject->make('UNKNOWN');
    }
}
