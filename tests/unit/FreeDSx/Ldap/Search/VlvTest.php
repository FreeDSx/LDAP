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
use FreeDSx\Ldap\Search\Vlv;
use unit\FreeDSx\Ldap\LdapTestCase;

class VlvTest extends LdapTestCase
{
    /**
     * @var Vlv
     */
    protected $vlv;

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

        $this->search = Operations::search(Filters::and(
            Filters::equal('objectClass', 'inetOrgPerson'),
            Filters::startsWith('cn','B')
        ), 'sn', 'givenName');
        $this->vlv = new Vlv($this->client, $this->search, 'sn');
    }

    protected function tearDown(): void
    {
        try {
            $this->client->unbind();
        } catch (\Exception|\Throwable $e) {
        }
    }

    public function testVlv()
    {
        $this->assertEquals(101, $this->vlv->getEntries()->count());
        $this->assertEquals(453, $this->vlv->listSize());
        $this->assertEquals(1, $this->vlv->listOffset());
        $this->assertTrue($this->vlv->isAtStartOfList());

        $this->vlv->moveForward(100);
        $this->assertEquals(101, $this->vlv->getEntries()->count());
        $this->assertEquals(101, $this->vlv->listOffset());

        $this->vlv->moveTo(300);
        $this->assertEquals(101, $this->vlv->getEntries()->count());
        $this->assertEquals(300, $this->vlv->listOffset());

        $this->vlv->moveBackward(100);
        $this->assertEquals(101, $this->vlv->getEntries()->count());
        $this->assertEquals(200, $this->vlv->listOffset());

        $this->vlv->moveTo($this->vlv->listSize());
        $this->assertEquals(1, $this->vlv->getEntries()->count());
        $this->assertTrue($this->vlv->isAtEndOfList());
    }

    public function testVlvAsPercentage()
    {
        $this->search = Operations::search(Filters::and(
            Filters::equal('objectClass', 'inetOrgPerson'),
            Filters::startsWith('cn','E')
        ), 'sn', 'givenName');
        $this->vlv = new Vlv($this->client, $this->search, 'sn');

        $this->vlv->asPercentage(true);
        $this->vlv->beforePosition(100);
        $this->vlv->moveTo(50);

        $this->assertEquals(201, $this->vlv->getEntries()->count());
        $this->assertGreaterThan(215, $this->vlv->listOffset());
        $this->assertLessThan(225, $this->vlv->listOffset());

        $this->vlv->moveForward(25);
        $this->assertEquals(201, $this->vlv->getEntries()->count());
        $this->assertGreaterThan(325, $this->vlv->listOffset());
        $this->assertLessThan(335, $this->vlv->listOffset());

        $this->vlv->moveBackward(50);
        $this->assertEquals(201, $this->vlv->getEntries()->count());
        $this->assertGreaterThan(105, $this->vlv->listOffset());
        $this->assertLessThan(115, $this->vlv->listOffset());

        $this->assertEquals(25, $this->vlv->position());
        $this->assertEquals(440, $this->vlv->listSize());

        $this->vlv->moveTo(100);
        $this->vlv->getEntries()->count();
        $this->assertTrue($this->vlv->isAtEndOfList());

        $this->vlv->moveTo(1);
        $this->vlv->getEntries();
        $this->assertTrue($this->vlv->isAtStartOfList());
    }
}
