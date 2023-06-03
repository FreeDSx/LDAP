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

namespace integration\FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Search\RangeRetrieval;
use integration\FreeDSx\Ldap\LdapTestCase;

class RangeRetrievalTest extends LdapTestCase
{
    private LdapClient $client;

    private RangeRetrieval $range;

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
    
    public function testRetrieveAll(): void
    {
        $result = $this->range->getAllValues(
            'cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com',
            'member'
        );

        $this->assertSame(
            10001,
            count($result->getValues())
        );
    }

    public function testHasRanged(): void
    {
        $entry = $this->client->readOrFail('cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com');

        $this->assertTrue($this->range->hasRanged(
            $entry,
            'member'
        ));
        $this->assertFalse($this->range->hasRanged(
            $entry,
            'description'
        ));
    }

    public function testGetRanged(): void
    {
        $entry = $this->client->readOrFail('cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com');

        $this->assertInstanceOf(
            Attribute::class,
            $this->range->getRanged(
                $entry,
                'member'
            )
        );
        $this->assertNull($this->range->getRanged(
            $entry,
            'description'
        ));
    }

    public function testGetAllRanged(): void
    {
        $allUsers = $this->client->readOrFail('cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com');
        $adminUsers = $this->client->readOrFail('cn=Administrative Users,ou=FreeDSx-Test,dc=example,dc=com');

        $this->assertCount(
            1,
            $this->range->getAllRanged($allUsers)
        );
        $this->assertCount(
            0,
            $this->range->getAllRanged($adminUsers)
        );
    }

    public function testPagingRangedValues(): void
    {
        $members = $this->client->readOrFail(
            'cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com',
            ['member;range=0-*']
        )->get('member');

        $this->assertInstanceOf(
            Attribute::class,
            $members,
        );
        $this->assertTrue($this->range->hasMoreValues($members));

        $all = $members->getValues();
        while ($this->range->hasMoreValues($members)) {
            $members = $this->range->getMoreValues(
                'cn=All Employees,ou=FreeDSx-Test,dc=example,dc=com',
                $members
            );
            $all = array_merge(
                $all,
                $members->getValues(),
            );
        }

        $this->assertCount(
            10001,
            $all
        );
    }
}
