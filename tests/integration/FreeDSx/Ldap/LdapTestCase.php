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

use FreeDSx\Ldap\LdapClient;
use PHPUnit\Framework\TestCase;
use Throwable;

class LdapTestCase extends TestCase
{
    protected static ?bool $isActiveDirectory = null;

    /**
     * @param array<string, mixed> $options
     */
    protected function getClient(array $options = []): LdapClient
    {
        return new LdapClient(array_merge(
            [
                'servers' => $_ENV['LDAP_SERVER'],
                'port' => $_ENV['LDAP_PORT'],
                'ssl_ca_cert' => $_ENV['LDAP_CA_CERT'] === ''
                    ? __DIR__ . '/../../../resources/cert/ca.crt'
                    : $_ENV['LDAP_CA_CERT'],
                'base_dn' => $_ENV['LDAP_BASE_DN'],
            ],
            $options,
        ));
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
