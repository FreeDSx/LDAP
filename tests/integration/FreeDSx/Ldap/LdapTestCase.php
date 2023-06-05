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

namespace integration\FreeDSx\Ldap;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\LdapClient;
use PHPUnit\Framework\TestCase;
use Throwable;

class LdapTestCase extends TestCase
{
    protected static ?bool $isActiveDirectory = null;

    protected function makeOptions(): ClientOptions
    {
        return (new ClientOptions())
            ->setBaseDn((string) $_ENV['LDAP_BASE_DN'])
            ->setServers([(string) $_ENV['LDAP_SERVER']])
            ->setSslCaCert(
                $_ENV['LDAP_CA_CERT'] === ''
                    ? __DIR__ . '/../../../resources/cert/ca.crt'
                    : (string) $_ENV['LDAP_CA_CERT']
            )
            ->setBaseDn((string) $_ENV['LDAP_BASE_DN']);
    }

    protected function getClient(?ClientOptions $options = null): LdapClient
    {
        return new LdapClient($options ?? $this->makeOptions());
    }

    protected function bindClient(LdapClient $client): void
    {
        $client->bind(
            $_ENV['LDAP_USERNAME'],
            $_ENV['LDAP_PASSWORD'],
        );
    }

    protected function isActiveDirectory(): bool
    {
        if (self::$isActiveDirectory === null) {
            $client = $this->getClient();

            try {
                self::$isActiveDirectory = $client->readOrFail('')
                    ->has('forestFunctionality');
            } catch (Throwable $e) {
                self::$isActiveDirectory = false;
            } finally {
                $client->unbind();
            }
        }

        return self::$isActiveDirectory;
    }
}
