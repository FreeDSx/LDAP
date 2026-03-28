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

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\CramMD5MechanismOptionsBuilder;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\DigestMD5MechanismOptionsBuilder;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderFactory;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\PlainMechanismOptionsBuilder;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\ScramMechanismOptionsBuilder;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\SaslHandlerInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Combined interface so PHPUnit can mock both at once.
 */
interface SaslRequestHandlerInterface extends RequestHandlerInterface, SaslHandlerInterface {}

final class MechanismOptionsBuilderFactoryTest extends TestCase
{
    private MechanismOptionsBuilderFactory $subject;

    private RequestHandlerInterface&MockObject $mockDispatcher;

    private SaslRequestHandlerInterface&MockObject $mockSaslDispatcher;

    protected function setUp(): void
    {
        $this->subject = new MechanismOptionsBuilderFactory();
        $this->mockDispatcher = $this->createMock(RequestHandlerInterface::class);
        $this->mockSaslDispatcher = $this->createMock(SaslRequestHandlerInterface::class);
    }

    public function test_make_plain_with_non_sasl_dispatcher_returns_plain_builder(): void
    {
        self::assertInstanceOf(
            PlainMechanismOptionsBuilder::class,
            $this->subject->make('PLAIN', $this->mockDispatcher)
        );
    }

    public function test_make_plain_with_sasl_dispatcher_returns_plain_builder(): void
    {
        self::assertInstanceOf(
            PlainMechanismOptionsBuilder::class,
            $this->subject->make('PLAIN', $this->mockSaslDispatcher)
        );
    }

    public function test_make_cram_md5_with_sasl_dispatcher_returns_cram_md5_builder(): void
    {
        self::assertInstanceOf(
            CramMD5MechanismOptionsBuilder::class,
            $this->subject->make('CRAM-MD5', $this->mockSaslDispatcher)
        );
    }

    public function test_make_digest_md5_with_sasl_dispatcher_returns_digest_md5_builder(): void
    {
        self::assertInstanceOf(
            DigestMD5MechanismOptionsBuilder::class,
            $this->subject->make('DIGEST-MD5', $this->mockSaslDispatcher)
        );
    }

    public function test_make_scram_sha256_with_sasl_dispatcher_returns_scram_builder(): void
    {
        self::assertInstanceOf(
            ScramMechanismOptionsBuilder::class,
            $this->subject->make('SCRAM-SHA-256', $this->mockSaslDispatcher)
        );
    }

    public function test_make_cram_md5_with_non_sasl_dispatcher_throws(): void
    {
        self::expectException(RuntimeException::class);

        $this->subject->make('CRAM-MD5', $this->mockDispatcher);
    }

    public function test_make_unknown_mechanism_throws(): void
    {
        self::expectException(RuntimeException::class);

        $this->subject->make('UNKNOWN', $this->mockSaslDispatcher);
    }
}
