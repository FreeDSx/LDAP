<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace unit\FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Search\RangeRetrieval;
use unit\FreeDSx\Ldap\LdapTestCase;

class RangeRetrievalTest extends LdapTestCase
{
    /**
     * @var LdapClient
     */
    protected $client;

    /**
     * @var RangeRetrieval
     */
    protected $range;

    public function setUp(): void
    {
        if (!$this->isActiveDirectory()) {
            $this->markTestSkipped('Range retrieval is only testable against Active Directory.');
        } else {
            $this->client = $this->getClient();
            $this->bindClient($this->client);
            $this->range = new RangeRetrieval($this->client);
        }
    }

    public function tearDown(): void
    {
        try {
            $this->client->unbind();
        } catch (\Exception|\Throwable $e) {
        }
    }
    
    public function testRetrieveAll()
    {
        $result = $this->range->getAllValues('cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com', 'member');

        $this->assertEquals(10001, count($result->getValues()));
    }

    public function testHasRanged()
    {
        $entry = $this->client->read('cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com');

        $this->assertTrue($this->range->hasRanged($entry, 'member'));
        $this->assertFalse($this->range->hasRanged($entry, 'description'));
    }

    public function testGetRanged()
    {
        $entry = $this->client->read('cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com');

        $this->assertInstanceOf(Attribute::class, $this->range->getRanged($entry, 'member'));
        $this->assertNull($this->range->getRanged($entry, 'description'));
    }

    public function testGetAllRanged()
    {
        $allUsers = $this->client->read('cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com');
        $adminUsers = $this->client->read('cn=Administrative Users,ou=FreeDSx-Test,dc=example,dc=com');

        $this->assertCount(1, $this->range->getAllRanged($allUsers));
        $this->assertCount(0, $this->range->getAllRanged($adminUsers));
    }

    public function testPagingRangedValues()
    {
        $members = $this->client->read('cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com', ['member;range=0-*'])->get('member');
        $this->assertTrue($this->range->hasMoreValues($members));

        $all = $members->getValues();
        while ($this->range->hasMoreValues($members)) {
            $members = $this->range->getMoreValues('cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com', $members);
            $all = array_merge($all, $members->getValues());
        }

        $this->assertCount(10001, $all);
    }
}
