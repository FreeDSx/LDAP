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

namespace Tests\Integration\FreeDSx\Ldap\Runner\Concern;

use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;
use Throwable;

trait TlsTestsTrait
{
    use RawClientQueueTrait;

    public function testItCanStartTLSThenStillPerformOperations(): void
    {
        $this->ldapClient()->startTls();
        $result = $this->ldapClient()->read();

        $this->assertNotNull($result);
    }

    public function testItDiscardsPlaintextPipelinedBehindStartTls(): void
    {
        $queue = $this->rawQueue(
            timeoutRead: 2,
            validateSslCert: false,
        );

        $queue->sendMessage(
            new LdapMessageRequest(1, Operations::extended(ExtendedRequest::OID_START_TLS)),
            new LdapMessageRequest(2, Operations::whoami()),
        );

        $startTls = $queue->getMessage(1)->getResponse();

        $this->assertInstanceOf(
            ExtendedResponse::class,
            $startTls,
        );
        $this->assertSame(
            ResultCode::SUCCESS,
            $startTls->getResultCode(),
        );

        $queue->encrypt();
        $injected = null;

        try {
            $injected = $queue->getMessage();
        } catch (Throwable) {
            // Nothing to read is the expected outcome
            // The injected PDU was dropped with the plaintext buffer.
        } finally {
            $queue->close();
        }

        $this->assertNull(
            $injected,
            'A PDU pipelined ahead of the upgrade must not be answered over the encrypted channel.',
        );
    }

    public function testItCanRunOverSSLOnly(): void
    {
        $this->stopServer();
        $this->createServerProcess('ssl');

        $result = $this->ldapClient()->read('');
        $this->assertNotNull($result);
    }

    public function testItRefusesASimpleBindInTheClearWhenConfidentialityIsRequired(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', ['--require-confidentiality=bind']);

        try {
            $this->ldapClient()->bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            );
            $this->fail('Expected the bind to be refused.');
        } catch (BindException $e) {
            $this->assertSame(
                ResultCode::CONFIDENTIALITY_REQUIRED,
                $e->getCode(),
            );
        }
    }

    public function testItAcceptsTheSameBindAfterStartTLS(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', ['--require-confidentiality=bind']);

        $this->ldapClient()->startTls();
        $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        $this->assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }

    public function testItAcceptsABindOverSSLWhenConfidentialityIsRequired(): void
    {
        $this->stopServer();
        $this->createServerProcess('ssl', ['--require-confidentiality=bind']);

        $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        $this->assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }

    public function testRequiringAllOperationsStillPermitsStartTLS(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', ['--require-confidentiality=all']);

        $this->ldapClient()->startTls();
        $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        $this->assertNotNull($this->ldapClient()->read(''));
    }
}
