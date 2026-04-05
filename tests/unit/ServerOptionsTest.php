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

namespace Tests\Unit\FreeDSx\Ldap;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;

final class ServerOptionsTest extends TestCase
{
    private ServerOptions $subject;

    protected function setUp(): void
    {
        $this->subject = new ServerOptions();
    }

    public function test_sasl_mechanisms_are_empty_by_default(): void
    {
        self::assertSame(
            [],
            $this->subject->getSaslMechanisms(),
        );
    }

    public function test_it_can_set_supported_sasl_mechanisms(): void
    {
        $this->subject->setSaslMechanisms(
            ServerOptions::SASL_PLAIN,
            ServerOptions::SASL_CRAM_MD5,
        );

        self::assertSame(
            [ServerOptions::SASL_PLAIN, ServerOptions::SASL_CRAM_MD5],
            $this->subject->getSaslMechanisms(),
        );
    }

    public function test_it_throws_for_an_unsupported_sasl_mechanism(): void
    {
        self::expectException(InvalidArgumentException::class);

        $this->subject->setSaslMechanisms('GSSAPI');
    }

    public function test_it_throws_for_any_unsupported_mechanism_in_the_list(): void
    {
        self::expectException(InvalidArgumentException::class);

        $this->subject->setSaslMechanisms(ServerOptions::SASL_PLAIN, 'GSSAPI');
    }

    public function test_max_connections_defaults_to_zero(): void
    {
        self::assertSame(0, $this->subject->getMaxConnections());
    }

    public function test_it_can_set_max_connections(): void
    {
        $this->subject->setMaxConnections(500);

        self::assertSame(500, $this->subject->getMaxConnections());
    }

    public function test_shutdown_timeout_defaults_to_fifteen_seconds(): void
    {
        self::assertSame(15, $this->subject->getShutdownTimeout());
    }

    public function test_it_can_set_shutdown_timeout(): void
    {
        $this->subject->setShutdownTimeout(30);

        self::assertSame(30, $this->subject->getShutdownTimeout());
    }

    public function test_it_accepts_all_defined_mechanism_constants(): void
    {
        $this->subject->setSaslMechanisms(
            ServerOptions::SASL_PLAIN,
            ServerOptions::SASL_CRAM_MD5,
            ServerOptions::SASL_DIGEST_MD5,
            ServerOptions::SASL_SCRAM_SHA_1,
            ServerOptions::SASL_SCRAM_SHA_1_PLUS,
            ServerOptions::SASL_SCRAM_SHA_224,
            ServerOptions::SASL_SCRAM_SHA_224_PLUS,
            ServerOptions::SASL_SCRAM_SHA_256,
            ServerOptions::SASL_SCRAM_SHA_256_PLUS,
            ServerOptions::SASL_SCRAM_SHA_384,
            ServerOptions::SASL_SCRAM_SHA_384_PLUS,
            ServerOptions::SASL_SCRAM_SHA_512,
            ServerOptions::SASL_SCRAM_SHA_512_PLUS,
            ServerOptions::SASL_SCRAM_SHA3_512,
            ServerOptions::SASL_SCRAM_SHA3_512_PLUS,
        );

        self::assertCount(
            15,
            $this->subject->getSaslMechanisms(),
        );
    }
}
