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

use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

class LdapProxyTest extends ServerTestCase
{
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldapproxy',
            'tcp',
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldapproxy');
        parent::setUp();
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
                'organizationalUnit'
            ),
            'ou'
        );
        $paging = $this->ldapClient()
            ->paging($search);

        $entries = $paging->getEntries(4);

        $this->assertCount(
            4,
            $entries
        );

        while ($paging->hasEntries()) {
            $entries->add(...$paging->getEntries(4)->toArray());
        }

        $this->assertCount(
            12,
            $entries
        );
    }

    protected function authenticate(): void
    {
        $this->ldapClient()->bind(
            (string) getenv('LDAP_USERNAME'),
            (string) getenv('LDAP_PASSWORD'),
        );
    }
}
