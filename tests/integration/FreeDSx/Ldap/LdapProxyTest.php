<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace integration\FreeDSx\Ldap;

use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

class LdapProxyTest extends ServerTestCase
{
    protected $serverExec = 'ldapproxy';

    public function setUp(): void
    {
        parent::setUp();

        $this->createServerProcess('tcp');
    }

    public function testItBindsToTheProxy()
    {
        $this->authenticate();

        $this->assertNotEmpty($this->client->whoami());
    }

    public function testItRetrievesTheRootDse()
    {
        $this->authenticate();
        $rootDse = $this->client->read();

        $this->assertNotEmpty($rootDse->toArray());
    }

    public function testItCanHandlePaging()
    {
        $this->authenticate();

        $search = Operations::search(Filters::equal('objectClass', 'inetOrgPerson'), 'cn');
        $paging = $this->client->paging($search);

        $entries = $paging->getEntries();
        $this->assertEquals(1000, $entries->count());

        while ($paging->hasEntries()) {
            $entries->add(...$paging->getEntries());
        }

        $this->assertEquals(10001, $entries->count());
    }

    protected function authenticate(): void
    {
        $this->client->bind(
            $_ENV['LDAP_USERNAME'],
            $_ENV['LDAP_PASSWORD']
        );
    }
}
