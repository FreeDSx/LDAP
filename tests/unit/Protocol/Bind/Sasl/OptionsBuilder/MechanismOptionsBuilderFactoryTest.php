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
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\DigestMD5MechanismOptionsBuilder;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderFactory;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\PlainMechanismOptionsBuilder;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\ScramMechanismOptionsBuilder;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class MechanismOptionsBuilderFactoryTest extends TestCase
{
    private PasswordAuthenticatableInterface&MockObject $mockAuthenticator;

    private MechanismOptionsBuilderFactory $subject;

    protected function setUp(): void
    {
        $this->mockAuthenticator = $this->createMock(PasswordAuthenticatableInterface::class);
        $this->subject = new MechanismOptionsBuilderFactory($this->mockAuthenticator);
    }

    public function test_make_plain_returns_plain_builder(): void
    {
        self::assertInstanceOf(
            PlainMechanismOptionsBuilder::class,
            $this->subject->make('PLAIN')
        );
    }

    public function test_make_cram_md5_returns_cram_md5_builder(): void
    {
        self::assertInstanceOf(
            CramMD5MechanismOptionsBuilder::class,
            $this->subject->make('CRAM-MD5')
        );
    }

    public function test_make_digest_md5_returns_digest_md5_builder(): void
    {
        self::assertInstanceOf(
            DigestMD5MechanismOptionsBuilder::class,
            $this->subject->make('DIGEST-MD5')
        );
    }

    public function test_make_scram_sha256_returns_scram_builder(): void
    {
        self::assertInstanceOf(
            ScramMechanismOptionsBuilder::class,
            $this->subject->make('SCRAM-SHA-256')
        );
    }

    public function test_make_unknown_mechanism_throws(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::OTHER);

        $this->subject->make('UNKNOWN');
    }
}
