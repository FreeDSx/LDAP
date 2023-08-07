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

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\Paging;
use FreeDSx\Ldap\Search\Result\EntryResult;
use integration\FreeDSx\Ldap\LdapTestCase;
use Throwable;

class PagingTest extends LdapTestCase
{
    private Paging $paging;

    private SearchRequest $search;

    private LdapClient $client;

    protected function setUp(): void
    {
        $this->client = $this->getClient();
        $this->bindClient($this->client);

        $this->search = Operations::search(
            Filters::equal(
                'objectClass',
                'inetOrgPerson'
            ),
            'cn'
        );

        $this->paging = new Paging(
            $this->client,
            $this->search
        );
    }

    protected function tearDown(): void
    {
        try {
            $this->client->unbind();
        } catch (Throwable) {
        }
    }

    public function testPagingAll(): void
    {
        $entries = $this->paging->getEntries();

        $this->assertSame(
            1000,
            $entries->count()
        );

        while ($this->paging->hasEntries()) {
            $entries->add(...$this->paging->getEntries());
        }

        $this->assertSame(
            10001,
            $entries->count()
        );
    }

    public function testPagingAllWhenEntryHandlerIsUsed(): void
    {
        $entries = new Entries();

        $operation = Operations::search(
            Filters::equal(
                'objectClass',
                'inetOrgPerson'
            ),
            'cn'
        );
        $operation->useEntryHandler(fn (EntryResult $result) => $entries->add($result->getEntry()));

        $this->paging = $this->client->paging($operation);

        while ($this->paging->hasEntries()) {
            $this->paging->getEntries();
        }

        $this->assertSame(
            10001,
            $entries->count()
        );
    }

    public function testPagingSpecificSize(): void
    {
        $entries = $this->paging->getEntries(100);

        $this->assertSame(
            100,
            $entries->count()
        );

        $this->assertTrue($this->paging->hasEntries());

        $this->paging->end();

        $this->assertFalse($this->paging->hasEntries());
    }
}
