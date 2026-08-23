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

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\LdapClient;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;
use Throwable;

class LdapTestCase extends TestCase
{
    use RequiresExtensionsTrait;

    protected static ?bool $isActiveDirectory = null;

    /**
     * @var LdapClient[]
     */
    private array $issuedClients = [];

    /**
     * Releases every socket handed out, so a later test that forks cannot inherit one a test forgot to close.
     */
    protected function tearDown(): void
    {
        foreach ($this->issuedClients as $client) {
            try {
                $client->disconnect();
            } catch (Throwable) {
                // The server may already be gone; only releasing the socket matters here.
            }
        }

        $this->issuedClients = [];

        parent::tearDown();
    }

    protected function makeOptions(): ClientOptions
    {
        return (new ClientOptions())
            ->setBaseDn((string) getenv('LDAP_BASE_DN'))
            ->setServers([(string) getenv('LDAP_SERVER')])
            ->setSslCaCert(
                $_ENV['LDAP_CA_CERT'] === ''
                    ? __DIR__ . '/../resources/cert/ca.crt'
                    : (string) getenv('LDAP_CA_CERT'),
            )
            ->setBaseDn((string) getenv('LDAP_BASE_DN'));
    }

    protected function getClient(?ClientOptions $options = null): LdapClient
    {
        $client = new LdapClient($options ?? $this->makeOptions());
        $this->issuedClients[] = $client;

        return $client;
    }

    protected function bindClient(LdapClient $client): void
    {
        $client->bind(
            (string) getenv('LDAP_USERNAME'),
            (string) getenv('LDAP_PASSWORD'),
        );
    }

    protected function isActiveDirectory(): bool
    {
        if (self::$isActiveDirectory === null) {
            $client = $this->getClient();

            try {
                self::$isActiveDirectory = $client->readOrFail('')
                    ->has('forestFunctionality');
            } catch (Throwable) {
                self::$isActiveDirectory = false;
            } finally {
                $client->unbind();
            }
        }

        return self::$isActiveDirectory;
    }
}
