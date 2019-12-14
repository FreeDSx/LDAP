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
    protected $client;

    /**
     * @var DirSync
     */
    protected $dirSync;

    /**
     * @var FilterInterface
     */
    protected $filter;

    public function setUp(): void
    {
        if (!$this->isActiveDirectory()) {
            $this->markTestSkipped('Range retrieval is only testable against Active Directory.');
        }
        $this->client = $this->getClient();
        $this->bindClient($this->client);

        $this->filter = Filters::and(
            Filters::equal('objectClass', 'inetOrgPerson'),
            Filters::not(Filters::equal('isDeleted', 'TRUE'))
        );
        $this->dirSync = new DirSync($this->client, null, $this->filter, 'description');
    }

    public function testPagingSync()
    {
        $all = $this->dirSync->getChanges();

        while ($this->dirSync->hasChanges()) {
            $all->add(...$this->dirSync->getChanges());
        }
        $this->assertCount(10001, $all);

        $entry = $this->client->read('cn=Vivie Niebudek,ou=Administrative,ou=FreeDSx-Test,dc=example,dc=com');
        $entry->set('description', 'foobar '.rand());
        $this->client->update($entry);

        $this->assertCount(1, $this->dirSync->getChanges());
    }
}
