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

use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

class LdapProxyTest extends ServerTestCase
{
    public function setUp(): void
    {
        $this->setServerMode('ldapproxy');

        parent::setUp();

        $this->createServerProcess('tcp');
    }

    public function testItBindsToTheProxy(): void
    {
        $this->authenticate();

        $this->assertNotEmpty($this->ldapClient()->whoami());
    }

    public function testItRetrievesTheRootDse(): void
    {
        $this->authenticate();
        $rootDse = $this->ldapClient()->readOrFail();

        $this->assertNotEmpty($rootDse->toArray());
    }

    public function testItCanHandlePaging(): void
    {
        $this->authenticate();

        $search = Operations::search(
            Filters::equal(
                'objectClass',
                'inetOrgPerson'
            ),
            'cn'
        );
        $paging = $this->ldapClient()
            ->paging($search);

        $entries = $paging->getEntries();

        $this->assertSame(
            1000,
            $entries->count()
        );

        while ($paging->hasEntries()) {
            $entries->add(...$paging->getEntries()->toArray());
        }

        $this->assertSame(
            10001,
            $entries->count()
        );
    }

    protected function authenticate(): void
    {
        $this->ldapClient()->bind(
            $_ENV['LDAP_USERNAME'],
            $_ENV['LDAP_PASSWORD']
        );
    }
}
