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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\CramMD5MechanismOptionsBuilder;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderFactory;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\PlainMechanismOptionsBuilder;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\ScramMechanismOptionsBuilder;
use FreeDSx\Ldap\Server\Backend\Auth\HashCostCeiling;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashScheme;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\Auth\SaslIdentity;
use FreeDSx\Ldap\Server\Config\PasswordHashLimits;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\PlainOptions;
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
            $this->subject->make(MechanismName::PLAIN),
        );
    }

    public function test_make_cram_md5_returns_cram_md5_builder(): void
    {
        self::assertInstanceOf(
            CramMD5MechanismOptionsBuilder::class,
            $this->subject->make(MechanismName::CRAM_MD5),
        );
    }

    public function test_make_digest_md5_is_not_supported(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::OTHER);

        $this->subject->make(MechanismName::DIGEST_MD5);
    }

    public function test_make_scram_sha256_returns_scram_builder(): void
    {
        self::assertInstanceOf(
            ScramMechanismOptionsBuilder::class,
            $this->subject->make(MechanismName::SCRAM_SHA256),
        );
    }

    public function test_make_unsupported_mechanism_throws(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::OTHER);

        $this->subject->make(MechanismName::ANONYMOUS);
    }

    public function test_plain_verifies_through_the_hash_service_it_was_given(): void
    {
        $this->mockAuthenticator
            ->method('getSaslIdentity')
            ->willReturn(new SaslIdentity(
                '{BCRYPT}' . password_hash(
                    'secret',
                    PASSWORD_BCRYPT,
                    ['cost' => 5],
                ),
                new Dn('cn=user,dc=foo,dc=bar'),
            ));
        $subject = new MechanismOptionsBuilderFactory(
            $this->mockAuthenticator,
            hashService: new PasswordHashService(
                hashCost: 4,
                ceiling: new HashCostCeiling(
                    new PasswordHashLimits(bcryptCost: 4),
                    PasswordHashScheme::Bcrypt,
                    4,
                ),
            ),
        );

        $options = $subject->make(MechanismName::PLAIN)->buildOptions(
            null,
            MechanismName::PLAIN,
        );

        self::assertInstanceOf(
            PlainOptions::class,
            $options,
        );
        $validate = $options->getValidate();
        self::assertNotNull($validate);
        self::assertFalse($validate(
            null,
            'user',
            'secret',
        ));
    }
}
