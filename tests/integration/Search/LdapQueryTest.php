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

namespace Tests\Integration\FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\LdapQuery;
use FreeDSx\Ldap\Search\Result\EntryResult;
use Tests\Integration\FreeDSx\Ldap\LdapTestCase;
use Throwable;

final class LdapQueryTest extends LdapTestCase
{
    private const BASE_DN = 'ou=FreeDSx-Test,dc=example,dc=com';

    private LdapClient $client;

    private LdapQuery $subject;

    protected function setUp(): void
    {
        $this->client = $this->getClient();
        $this->bindClient($this->client);
        $this->subject = $this->client
            ->query()
            ->from(self::BASE_DN);
    }

    protected function tearDown(): void
    {
        try {
            $this->client->unbind();
        } catch (Throwable) {
        }
    }

    public function testGetReturnsAllMatchingEntries(): void
    {
        $entries = $this->subject
            ->select('ou')
            ->andWhere(Filters::equal('objectClass', 'organizationalUnit'))
            ->get();

        $this->assertCount(12, $entries);
    }

    public function testGetWithAndWhereAccumulatesFilters(): void
    {
        $entries = $this->subject
            ->select('cn')
            ->andWhere(Filters::equal('objectClass', 'inetOrgPerson'))
            ->andWhere(Filters::startsWith('cn', 'A'))
            ->get();

        $this->assertCount(
            843,
            $entries,
        );
    }

    public function testGetWithOrWhereReturnsUnionOfResults(): void
    {
        $entries = $this->subject
            ->select('cn')
            ->orWhere(Filters::equal('cn', 'Birgit Pankhurst'))
            ->orWhere(Filters::equal('cn', 'Carmelina Esposito'))
            ->get();

        $this->assertCount(
            2,
            $entries,
        );
    }

    public function testSelectLimitsReturnedAttributes(): void
    {
        $entry = $this->subject
            ->select('cn')
            ->andWhere(Filters::equal('cn', 'Birgit Pankhurst'))
            ->first();

        $this->assertNotNull($entry);
        $this->assertNotNull($entry->get('cn'));
        $this->assertNull($entry->get('sn'));
    }

    public function testUseSingleLevelScopeSearchesDirectChildrenOnly(): void
    {
        $payrollDn = 'ou=Payroll,' . self::BASE_DN;

        $entries = $this->subject
            ->from($payrollDn)
            ->useSingleLevelScope()
            ->select('cn')
            ->andWhere(Filters::equal('objectClass', 'inetOrgPerson'))
            ->get();

        $this->assertNotEmpty($entries);

        foreach ($entries as $entry) {
            $this->assertSame(
                strtolower($payrollDn),
                strtolower((string) $entry->getDn()->getParent()?->toString()),
            );
        }
    }

    public function testFirstReturnsFirstMatchingEntry(): void
    {
        $entry = $this->subject
            ->select('cn')
            ->andWhere(Filters::equal('cn', 'Birgit Pankhurst'))
            ->first();

        $this->assertNotNull($entry);
        $this->assertSame(
            strtolower('cn=Birgit Pankhurst,ou=Janitorial,' . self::BASE_DN),
            strtolower($entry->getDn()->toString()),
        );
    }

    public function testFirstReturnsNullWhenNoEntryMatches(): void
    {
        $entry = $this->subject
            ->andWhere(Filters::equal('cn', 'ThisPersonDoesNotExist12345'))
            ->first();

        $this->assertNull($entry);
    }

    public function testPagingReturnsAllResultsAcrossPages(): void
    {
        $paging = $this->subject
            ->select('ou')
            ->andWhere(Filters::equal('objectClass', 'organizationalUnit'))
            ->paging(4);

        $entries = new Entries();
        while ($paging->hasEntries()) {
            $entries->add(...$paging->getEntries()->toArray());
        }

        $this->assertCount(
            12,
            $entries,
        );
    }

    public function testStreamYieldsAllMatchingResults(): void
    {
        $subject = $this->subject
            ->select('ou')
            ->andWhere(Filters::equal('objectClass', 'organizationalUnit'));

        $count = 0;
        foreach ($subject->stream() as $result) {
            $this->assertInstanceOf(EntryResult::class, $result);
            $this->assertNotNull($result->getEntry()->get('ou'));
            $count++;
        }

        $this->assertSame(12, $count);
    }

    public function testStreamYieldsResultsWithAccessibleMessageControls(): void
    {
        $subject = $this->subject
            ->select('cn')
            ->andWhere(Filters::equal('cn', 'Birgit Pankhurst'));

        foreach ($subject->stream() as $result) {
            $this->assertNotNull($result->getEntry());
            $this->assertNotNull($result->getMessage());
        }
    }
}
