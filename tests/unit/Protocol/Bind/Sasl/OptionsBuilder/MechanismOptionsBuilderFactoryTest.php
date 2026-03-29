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
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\RequestHandler\SaslHandlerInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Combined interface so PHPUnit can mock both at once.
 */
interface SaslBackendInterface extends LdapBackendInterface, SaslHandlerInterface {}

final class MechanismOptionsBuilderFactoryTest extends TestCase
{
    private LdapBackendInterface&MockObject $mockBackend;

    private SaslBackendInterface&MockObject $mockSaslBackend;

    private PasswordAuthenticatableInterface&MockObject $mockAuthenticator;

    protected function setUp(): void
    {
        $this->mockBackend = $this->createMock(LdapBackendInterface::class);
        $this->mockSaslBackend = $this->createMock(SaslBackendInterface::class);
        $this->mockAuthenticator = $this->createMock(PasswordAuthenticatableInterface::class);
    }

    public function test_make_plain_with_non_sasl_backend_returns_plain_builder(): void
    {
        $subject = new MechanismOptionsBuilderFactory($this->mockBackend);

        self::assertInstanceOf(
            PlainMechanismOptionsBuilder::class,
            $subject->make('PLAIN', $this->mockAuthenticator)
        );
    }

    public function test_make_plain_with_sasl_backend_returns_plain_builder(): void
    {
        $subject = new MechanismOptionsBuilderFactory($this->mockSaslBackend);

        self::assertInstanceOf(
            PlainMechanismOptionsBuilder::class,
            $subject->make('PLAIN', $this->mockAuthenticator)
        );
    }

    public function test_make_cram_md5_with_sasl_backend_returns_cram_md5_builder(): void
    {
        $subject = new MechanismOptionsBuilderFactory($this->mockSaslBackend);

        self::assertInstanceOf(
            CramMD5MechanismOptionsBuilder::class,
            $subject->make('CRAM-MD5', $this->mockAuthenticator)
        );
    }

    public function test_make_digest_md5_with_sasl_backend_returns_digest_md5_builder(): void
    {
        $subject = new MechanismOptionsBuilderFactory($this->mockSaslBackend);

        self::assertInstanceOf(
            DigestMD5MechanismOptionsBuilder::class,
            $subject->make('DIGEST-MD5', $this->mockAuthenticator)
        );
    }

    public function test_make_scram_sha256_with_sasl_backend_returns_scram_builder(): void
    {
        $subject = new MechanismOptionsBuilderFactory($this->mockSaslBackend);

        self::assertInstanceOf(
            ScramMechanismOptionsBuilder::class,
            $subject->make('SCRAM-SHA-256', $this->mockAuthenticator)
        );
    }

    public function test_make_cram_md5_with_non_sasl_backend_throws(): void
    {
        $subject = new MechanismOptionsBuilderFactory($this->mockBackend);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::OTHER);

        $subject->make('CRAM-MD5', $this->mockAuthenticator);
    }

    public function test_make_unknown_mechanism_throws(): void
    {
        $subject = new MechanismOptionsBuilderFactory($this->mockSaslBackend);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::OTHER);

        $subject->make('UNKNOWN', $this->mockAuthenticator);
    }
}
