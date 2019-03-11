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
    protected static $client;

    /**
     * @var RangeRetrieval
     */
    protected static $range;

    public static function setUpBeforeClass()
    {
        if (!self::isActiveDirectory()) {
            self::markTestSkipped('Range retrieval is only testable against Active Directory.');
        } else {
            self::$client = self::getClient();
            self::bindClient(self::$client);
            self::$range = new RangeRetrieval(self::$client);
        }
    }

    public static function tearDownAfterClass()
    {
        try {
            self::$client->unbind();
        } catch (\Exception|\Throwable $e) {
        }
    }
    
    public function testRetrieveAll()
    {
        $result = self::$range->getAllValues('cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com', 'member');

        $this->assertEquals(10001, count($result->getValues()));
    }

    public function testHasRanged()
    {
        $entry = self::$client->read('cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com');

        $this->assertTrue(self::$range->hasRanged($entry, 'member'));
        $this->assertFalse(self::$range->hasRanged($entry, 'description'));
    }

    public function testGetRanged()
    {
        $entry = self::$client->read('cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com');

        $this->assertInstanceOf(Attribute::class, self::$range->getRanged($entry, 'member'));
        $this->assertNull(self::$range->getRanged($entry, 'description'));
    }

    public function testGetAllRanged()
    {
        $allUsers = self::$client->read('cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com');
        $adminUsers = self::$client->read('cn=Administrative Users,ou=FreeDSx-Test,dc=example,dc=com');

        $this->assertCount(1, self::$range->getAllRanged($allUsers));
        $this->assertCount(0, self::$range->getAllRanged($adminUsers));
    }

    public function testPagingRangedValues()
    {
        $members = self::$client->read('cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com', ['member;range=0-*'])->get('member');
        $this->assertTrue(self::$range->hasMoreValues($members));

        $all = $members->getValues();
        while (self::$range->hasMoreValues($members)) {
            $members = self::$range->getMoreValues('cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com', $members);
            $all = array_merge($all, $members->getValues());
        }

        $this->assertCount(10001, $all);
    }
}
