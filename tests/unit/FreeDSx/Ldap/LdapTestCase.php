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
    protected static $isActiveDirectory;

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
     * @throws \FreeDSx\Ldap\Exception\OperationException
     */
    protected function bindClient(LdapClient $client) : void
    {
        $client->bind($_ENV['LDAP_USERNAME'], $_ENV['LDAP_PASSWORD']);
    }

    /**
     * @return bool
     * @throws \FreeDSx\Ldap\Exception\OperationException
     */
    protected function isActiveDirectory() : bool
    {
        if (self::$isActiveDirectory === null) {
            $client = $this->getClient();
            try {
                self::$isActiveDirectory = $client->read('')->has('forestFunctionality');
            } catch (\Exception|\Throwable $e) {
                self::$isActiveDirectory = false;
            } finally {
                $client->unbind();
            }
        }

        return self::$isActiveDirectory;
    }
}
