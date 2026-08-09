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

namespace Tests\Integration\FreeDSx\Ldap\Security;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\ExternalOptions;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\TestWorker;
use Throwable;

use function strtolower;

final class LdapExternalSaslServerTest extends ServerTestCase
{
    /**
     * Client cert with subject "/DC=bar/DC=foo/CN=extuser" -> maps to the seeded cn=extuser,dc=foo,dc=bar.
     */
    private const CLIENT_CERT = __DIR__ . '/../../resources/cert/test-cases/ext-client.crt';

    private const CLIENT_KEY = __DIR__ . '/../../resources/cert/test-cases/ext-client.key';

    /**
     * Client cert whose subject maps to cn=nobody,dc=foo,dc=bar, which is not seeded.
     */
    private const NOBODY_CERT = __DIR__ . '/../../resources/cert/test-cases/ext-nobody.crt';

    private const NOBODY_KEY = __DIR__ . '/../../resources/cert/test-cases/ext-nobody.key';

    /**
     * @var LdapClient[]
     */
    private array $certificateClients = [];

    public function setUp(): void
    {
        $this->setServerMode('ldap-server');

        parent::setUp();

        $this->createServerProcess(
            'ssl',
            ['--external'],
        );
    }

    public function tearDown(): void
    {
        foreach ($this->certificateClients as $client) {
            try {
                $client->unbind();
            } catch (Throwable) {
                // The connection may already be closed; ignore unbind failures.
            }
        }
        $this->certificateClients = [];

        parent::tearDown();
    }

    public function testItBindsViaSaslExternalAsTheCertificateIdentity(): void
    {
        $client = $this->clientWithCertificate(
            self::CLIENT_CERT,
            self::CLIENT_KEY,
        );

        $response = $client
            ->bindSasl(new ExternalOptions(), MechanismName::EXTERNAL)
            ->getResponse();

        self::assertInstanceOf(
            BindResponse::class,
            $response,
        );
        self::assertSame(
            0,
            $response->getResultCode(),
        );
        self::assertSame(
            'dn:cn=extuser,dc=foo,dc=bar',
            strtolower((string) $client->whoami()),
        );
    }

    public function testTheRootDseAdvertisesTheExternalMechanism(): void
    {
        $client = $this->clientWithCertificate(
            self::CLIENT_CERT,
            self::CLIENT_KEY,
        );
        $client->bindSasl(new ExternalOptions(), MechanismName::EXTERNAL);

        $rootDse = $client->read(
            '',
            ['supportedSaslMechanisms'],
        );

        self::assertNotNull($rootDse);
        self::assertContains(
            'EXTERNAL',
            $rootDse->get('supportedSaslMechanisms')?->getValues() ?? [],
        );
    }

    public function testAnUnmappedCertificateIsRejected(): void
    {
        $client = $this->clientWithCertificate(
            self::NOBODY_CERT,
            self::NOBODY_KEY,
        );

        $this->expectException(BindException::class);

        $client->bindSasl(new ExternalOptions(), MechanismName::EXTERNAL);
    }

    private function clientWithCertificate(
        string $cert,
        string $key,
    ): LdapClient {
        $client = new LdapClient(
            (new ClientOptions())
                ->setServers(['127.0.0.1'])
                ->setPort(TestWorker::port())
                ->setTransport('tcp')
                ->setUseSsl(true)
                ->setSslValidateCert(false)
                ->setSslCert($cert)
                ->setSslCertKey($key),
        );
        $this->certificateClients[] = $client;

        return $client;
    }
}
