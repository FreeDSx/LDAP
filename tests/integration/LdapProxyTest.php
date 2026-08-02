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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ReadEntry\PostReadResponseControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

final class LdapProxyTest extends ServerTestCase
{
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-proxy',
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
        $this->setServerMode('ldap-proxy');
        parent::setUp();
    }

    public function testItBindsToTheProxy(): void
    {
        $this->authenticateUser();

        self::assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }

    public function testItRetrievesTheRootDse(): void
    {
        $this->authenticateUser();

        self::assertNotEmpty($this->ldapClient()->readOrFail()->toArray());
    }

    public function testItForwardsWritesToUpstream(): void
    {
        $this->authenticateAdmin();
        $client = $this->ldapClient();
        $dn = 'cn=written,dc=foo,dc=bar';

        $client->create(Entry::fromArray(
            $dn,
            [
                'cn' => ['written'],
                'sn' => ['Written'],
                'objectClass' => ['inetOrgPerson'],
            ],
        ));
        self::assertTrue(
            $client->compare($dn, 'sn', 'Written'),
        );

        $client->send(Operations::modify(
            $dn,
            Change::replace('sn', 'Changed'),
        ));
        self::assertTrue(
            $client->compare($dn, 'sn', 'Changed'),
        );

        $client->delete($dn);
        self::assertNull($client->read($dn));
    }

    public function testItPagesThroughForwardedResults(): void
    {
        $this->authenticateUser();

        $paging = $this->ldapClient()->paging(
            Operations::search(
                Filters::equal(
                    'objectClass',
                    'inetOrgPerson',
                ),
            )->base('dc=foo,dc=bar'),
            5,
        );

        $entries = $paging->getEntries();
        while ($paging->hasEntries()) {
            $entries->add(...$paging->getEntries()->toArray());
        }

        // Upstream seeds 12 generated entries plus cn=user and cn=admin.
        self::assertCount(
            14,
            $entries,
        );
    }

    public function testItForwardsAResponseControlFromUpstream(): void
    {
        $this->authenticateAdmin();

        $response = $this->ldapClient()->send(
            Operations::add(Entry::fromArray(
                'ou=proxied-ctrl,dc=foo,dc=bar',
                [
                    'ou' => ['proxied-ctrl'],
                    'objectClass' => ['organizationalUnit'],
                ],
            )),
            Controls::postRead('ou'),
        );

        $postRead = $response?->controls()->get(Control::OID_POST_READ);
        self::assertInstanceOf(
            PostReadResponseControl::class,
            $postRead,
        );
        self::assertSame(
            ['proxied-ctrl'],
            $postRead->getEntry()->get('ou')?->getValues(),
        );
    }

    public function testItUpgradesTheDownstreamConnectionWithStartTls(): void
    {
        $this->ldapClient()->startTls();
        $this->authenticateUser();

        self::assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }
}
