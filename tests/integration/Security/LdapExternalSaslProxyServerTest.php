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
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\ExternalOptions;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\TestWorker;
use Throwable;

use function strtolower;

/**
 * End-to-end SASL EXTERNAL proxied authorization: the cert identity cn=extuser is granted the control over dc=foo,dc=bar.
 */
final class LdapExternalSaslProxyServerTest extends ServerTestCase
{
    private const CLIENT_CERT = __DIR__ . '/../../resources/cert/test-cases/ext-client.crt';

    private const CLIENT_KEY = __DIR__ . '/../../resources/cert/test-cases/ext-client.key';

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
            [
                '--external',
                '--external-allow-proxy',
            ],
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

    public function testItProxiesToAnotherIdentityWhenGranted(): void
    {
        $client = $this->clientWithCertificate();

        $client->bindSasl(
            (new ExternalOptions())->setAuthzId('dn:cn=user,dc=foo,dc=bar'),
            MechanismName::EXTERNAL,
        );

        self::assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            strtolower((string) $client->whoami()),
        );
    }

    public function testItBindsAsSelfWhenTheAuthzIdNamesTheCertificateIdentity(): void
    {
        $client = $this->clientWithCertificate();

        $client->bindSasl(
            (new ExternalOptions())->setAuthzId('dn:cn=extuser,dc=foo,dc=bar'),
            MechanismName::EXTERNAL,
        );

        self::assertSame(
            'dn:cn=extuser,dc=foo,dc=bar',
            strtolower((string) $client->whoami()),
        );
    }

    public function testItDeniesProxyingToAnUnresolvableIdentity(): void
    {
        $client = $this->clientWithCertificate();

        $this->expectException(BindException::class);

        $client->bindSasl(
            (new ExternalOptions())->setAuthzId('dn:cn=ghost,dc=foo,dc=bar'),
            MechanismName::EXTERNAL,
        );
    }

    private function clientWithCertificate(): LdapClient
    {
        $client = new LdapClient(
            (new ClientOptions())
                ->setServers(['127.0.0.1'])
                ->setPort(TestWorker::port())
                ->setTransport('tcp')
                ->setUseSsl(true)
                ->setSslValidateCert(false)
                ->setSslCert(self::CLIENT_CERT)
                ->setSslCertKey(self::CLIENT_KEY),
        );
        $this->certificateClients[] = $client;

        return $client;
    }
}
