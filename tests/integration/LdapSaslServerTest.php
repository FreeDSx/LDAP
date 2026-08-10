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
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\CramMD5Options;
use FreeDSx\Sasl\Options\PlainOptions;
use FreeDSx\Sasl\Options\ScramOptions;

final class LdapSaslServerTest extends ServerTestCase
{
    public function setUp(): void
    {
        $this->setServerMode('ldap-server');

        parent::setUp();

        $this->createServerProcess(
            'tcp',
            ['--sasl'],
        );
    }

    public function testItCanAuthenticateWithSaslPlain(): void
    {
        $response = $this->ldapClient()->bindSasl(
            (new PlainOptions())->setUsername('user')->setPassword('12345'),
            MechanismName::PLAIN,
        )->getResponse();

        $this->assertInstanceOf(BindResponse::class, $response);
        $this->assertSame(0, $response->getResultCode());
    }

    public function testSaslPlainFailsWithInvalidCredentials(): void
    {
        $this->expectException(BindException::class);

        $this->ldapClient()->bindSasl(
            (new PlainOptions())->setUsername('user')->setPassword('wrong'),
            MechanismName::PLAIN,
        );
    }

    public function testSaslPlainFailsWithUnknownUser(): void
    {
        $this->expectException(BindException::class);

        $this->ldapClient()->bindSasl(
            (new PlainOptions())->setUsername('nobody')->setPassword('12345'),
            MechanismName::PLAIN,
        );
    }

    public function testItCanAuthenticateWithSaslCramMD5(): void
    {
        $response = $this->ldapClient()->bindSasl(
            (new CramMD5Options())->setUsername('user')->setPassword('12345'),
            MechanismName::CRAM_MD5,
        )->getResponse();

        $this->assertInstanceOf(BindResponse::class, $response);
        $this->assertSame(0, $response->getResultCode());
    }

    public function testSaslCramMD5FailsWithInvalidCredentials(): void
    {
        $this->expectException(BindException::class);

        $this->ldapClient()->bindSasl(
            (new CramMD5Options())->setUsername('user')->setPassword('wrong'),
            MechanismName::CRAM_MD5,
        );
    }

    public function testItCanAuthenticateWithSaslScramSha256(): void
    {
        $response = $this->ldapClient()->bindSasl(
            (new ScramOptions())->setUsername('user')->setPassword('12345'),
            MechanismName::SCRAM_SHA256,
        )->getResponse();

        $this->assertInstanceOf(
            BindResponse::class,
            $response,
        );
        $this->assertSame(
            0,
            $response->getResultCode(),
        );
    }

    public function testSaslScramSha256FailsWithInvalidCredentials(): void
    {
        $this->expectException(BindException::class);

        $this->ldapClient()->bindSasl(
            (new ScramOptions())->setUsername('user')->setPassword('wrong'),
            MechanismName::SCRAM_SHA256,
        );
    }

    public function testRootDseAdvertisesSaslMechanisms(): void
    {
        $rootDse = $this->ldapClient()->read('', ['+']);

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
