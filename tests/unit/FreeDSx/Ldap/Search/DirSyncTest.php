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

use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Search\DirSync;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use unit\FreeDSx\Ldap\LdapTestCase;

class DirSyncTest extends LdapTestCase
{
    /**
     * @var LdapClient
     */
    protected static $client;

    /**
     * @var DirSync
     */
    protected static $dirSync;

    /**
     * @var FilterInterface
     */
    protected static $filter;

    public static function setUpBeforeClass()
    {
        if (!self::isActiveDirectory()) {
            self::markTestSkipped('Range retrieval is only testable against Active Directory.');
        } else {
            self::$client = self::getClient();
            self::bindClient(self::$client);

            self::$filter = Filters::and(
                Filters::equal('objectClass', 'inetOrgPerson'),
                Filters::not(Filters::equal('isDeleted', 'TRUE'))
            );
            self::$dirSync = new DirSync(self::$client, null, self::$filter, 'description');
        }
    }

    public function testPagingSync()
    {
        $all = self::$dirSync->getChanges();

        while (self::$dirSync->hasChanges()) {
            $all->add(...self::$dirSync->getChanges());
        }
        $this->assertCount(10001, $all);

        $entry = self::$client->read('cn=Vivie Niebudek,ou=Administrative,ou=FreeDSx-Test,dc=example,dc=com');
        $entry->set('description', 'foobar '.rand());
        self::$client->update($entry);

        $this->assertCount(1, self::$dirSync->getChanges());
    }
}
