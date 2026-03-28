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

namespace Tests\Integration\FreeDSx\Ldap;

use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\ServerOptions;

final class LdapSaslServerTest extends ServerTestCase
{
    public function setUp(): void
    {
        $this->setServerMode('ldapserver');

        parent::setUp();

        $this->createServerProcess(
            'tcp',
            'sasl'
        );
    }

    public function testItCanAuthenticateWithSaslPlain(): void
    {
        $response = $this->ldapClient()->bindSasl(
            ['username' => 'cn=user,dc=foo,dc=bar', 'password' => '12345'],
            ServerOptions::SASL_PLAIN,
        )->getResponse();

        $this->assertInstanceOf(BindResponse::class, $response);
        $this->assertSame(0, $response->getResultCode());
    }

    public function testSaslPlainFailsWithInvalidCredentials(): void
    {
        $this->expectException(BindException::class);

        $this->ldapClient()->bindSasl(
            ['username' => 'cn=user,dc=foo,dc=bar', 'password' => 'wrong'],
            ServerOptions::SASL_PLAIN,
        );
    }

    public function testItCanAuthenticateWithSaslCramMD5(): void
    {
        $response = $this->ldapClient()->bindSasl(
            ['username' => 'cn=user,dc=foo,dc=bar', 'password' => '12345'],
            ServerOptions::SASL_CRAM_MD5,
        )->getResponse();

        $this->assertInstanceOf(BindResponse::class, $response);
        $this->assertSame(0, $response->getResultCode());
    }

    public function testSaslCramMD5FailsWithInvalidCredentials(): void
    {
        $this->expectException(BindException::class);

        $this->ldapClient()->bindSasl(
            ['username' => 'cn=user,dc=foo,dc=bar', 'password' => 'wrong'],
            ServerOptions::SASL_CRAM_MD5,
        );
    }

    public function testItCanAuthenticateWithSaslScramSha256(): void
    {
        $response = $this->ldapClient()->bindSasl(
            ['username' => 'cn=user,dc=foo,dc=bar', 'password' => '12345'],
            ServerOptions::SASL_SCRAM_SHA_256,
        )->getResponse();

        $this->assertInstanceOf(
            BindResponse::class,
            $response
        );
        $this->assertSame(
            0,
            $response->getResultCode()
        );
    }

    public function testSaslScramSha256FailsWithInvalidCredentials(): void
    {
        $this->expectException(BindException::class);

        $this->ldapClient()->bindSasl(
            ['username' => 'cn=user,dc=foo,dc=bar', 'password' => 'wrong'],
            ServerOptions::SASL_SCRAM_SHA_256,
        );
    }

    public function testRootDseAdvertisesSaslMechanisms(): void
    {
        $rootDse = $this->ldapClient()->read('');

        $this->assertNotNull($rootDse);

        $mechanisms = $rootDse->toArray()['supportedSaslMechanisms'] ?? [];

        $this->assertContains(
            ServerOptions::SASL_PLAIN,
            $mechanisms,
        );
        $this->assertContains(
            ServerOptions::SASL_CRAM_MD5,
            $mechanisms,
        );
        $this->assertContains(
            ServerOptions::SASL_SCRAM_SHA_256,
            $mechanisms,
        );
    }
}
