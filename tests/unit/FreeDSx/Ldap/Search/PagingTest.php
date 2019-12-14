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
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\Paging;
use unit\FreeDSx\Ldap\LdapTestCase;

class PagingTest extends LdapTestCase
{
    /**
     * @var Paging
     */
    protected $paging;

    /**
     * @var SearchRequest
     */
    protected $search;

    /**
     * @var LdapClient
     */
    protected $client;

    protected function setUp(): void
    {
        $this->client = $this->getClient();
        $this->bindClient($this->client);

        $this->search = Operations::search(Filters::equal('objectClass', 'inetOrgPerson'),'cn');
        $this->paging = new Paging($this->client, $this->search);
    }

    protected function tearDown(): void
    {
        try {
            $this->client->unbind();
        } catch (\Exception|\Throwable $e) {
        }
    }

    public function testPagingAll()
    {
        $entries = $this->paging->getEntries();
        $this->assertEquals(1000, $entries->count());

        while ($this->paging->hasEntries()) {
            $entries->add(...$this->paging->getEntries());
        }

        $this->assertEquals(10001, $entries->count());
    }

    public function testPagingSpecificSize()
    {
        $entries = $this->paging->getEntries(100);
        $this->assertEquals(100, $entries->count());
        $this->assertTrue($this->paging->hasEntries());

        $this->paging->end();
        $this->assertFalse($this->paging->hasEntries());
    }
}
