<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace unit\FreeDSx\Ldap;

use FreeDSx\Ldap\LdapClient;
use PHPUnit\Framework\TestCase;

class LdapTestCase extends TestCase
{
    /**
     * @var bool
     */
    protected $isActiveDirectory;

    /**
     * @param array $options
     * @return LdapClient
     */
    protected function getClient(array $options = []) : LdapClient
    {
        $default = [
            'servers' => $_ENV['LDAP_SERVER'],
            'port' => $_ENV['LDAP_PORT'],
            'ssl_ca_cert' => $_ENV['LDAP_CA_CERT'] === '' ? __DIR__.'/../../../resources/cert/ca.crt' : $_ENV['LDAP_CA_CERT'],
            'base_dn' => $_ENV['LDAP_BASE_DN'],
        ];

        return new LdapClient(array_merge($default, $options));
    }

    /**
     * @param LdapClient $client
     * @throws \FreeDSx\Ldap\Exception\BindException
     */
    protected function bindClient(LdapClient $client) : void
    {
        $client->bind($_ENV['LDAP_USERNAME'], $_ENV['LDAP_PASSWORD']);
    }

    /**
     * @return bool
     */
    protected function isActiveDirectory() : bool
    {
        if ($this->isActiveDirectory === null) {
            try {
                $this->isActiveDirectory = $this->getClient()->read('')->has('forestFunctionality');
            } catch (\Exception|\Throwable $e) {
                $this->isActiveDirectory = false;
            }
        }

        return $this->isActiveDirectory;
    }
}
