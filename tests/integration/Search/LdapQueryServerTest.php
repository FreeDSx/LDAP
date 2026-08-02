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
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\LdapQuery;
use FreeDSx\Ldap\Search\Result\EntryResult;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

final class LdapQueryServerTest extends ServerTestCase
{
    private const ENTRY_COUNT = 5;

    /**
     * The fixed seed adds cn=user and cn=admin on top of the generated entries.
     */
    private const SEEDED_PERSON_COUNT = 2;

    private const BASE_DN = 'dc=foo,dc=bar';

    private LdapQuery $subject;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-server',
            'tcp',
            ['--entries=' . self::ENTRY_COUNT],
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-server');
        parent::setUp();
        $this->authenticateUser();
        $this->subject = $this->ldapClient()
            ->query()
            ->from(self::BASE_DN);
    }

    public function testGetReturnsAllMatchingEntries(): void
    {
        $entries = $this->subject
            ->select('cn')
            ->andWhere(Filters::equal('objectClass', 'inetOrgPerson'))
            ->get();

        $this->assertCount(
            self::ENTRY_COUNT + self::SEEDED_PERSON_COUNT,
            $entries,
        );
    }

    public function testGetWithAndWhereAccumulatesFilters(): void
    {
        $entries = $this->subject
            ->select('cn')
            ->andWhere(Filters::equal('objectClass', 'inetOrgPerson'))
            ->andWhere(Filters::equal('sn', 'User'))
            ->get();

        $this->assertCount(
            1,
            $entries,
        );
    }

    public function testGetWithOrWhereReturnsUnionOfResults(): void
    {
        $entries = $this->subject
            ->select('cn')
            ->orWhere(Filters::equal('cn', 'user'))
            ->orWhere(Filters::equal('cn', 'entry-1'))
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
            ->andWhere(Filters::equal('cn', 'user'))
            ->first();

        $this->assertNotNull($entry);
        $this->assertNotNull($entry->get('cn'));
        $this->assertNull($entry->get('sn'));
    }

    public function testUseSingleLevelScopeSearchesDirectChildrenOnly(): void
    {
        $entries = $this->subject
            ->useSingleLevelScope()
            ->select('cn')
            ->andWhere(Filters::equal('objectClass', 'inetOrgPerson'))
            ->get();

        $this->assertNotEmpty($entries);

        foreach ($entries as $entry) {
            $this->assertSame(
                self::BASE_DN,
                strtolower((string) $entry->getDn()->getParent()?->toString()),
            );
        }
    }

    public function testFirstReturnsFirstMatchingEntry(): void
    {
        $entry = $this->subject
            ->select('cn')
            ->andWhere(Filters::equal('cn', 'user'))
            ->first();

        $this->assertNotNull($entry);
        $this->assertSame(
            'cn=user,' . self::BASE_DN,
            $entry->getDn()->toString(),
        );
    }

    public function testFirstReturnsNullWhenNoEntryMatches(): void
    {
        $entry = $this->subject
            ->andWhere(Filters::equal('cn', 'nobody-here'))
            ->first();

        $this->assertNull($entry);
    }

    public function testPagingReturnsAllResultsAcrossPages(): void
    {
        $paging = $this->subject
            ->select('cn')
            ->andWhere(Filters::equal('objectClass', 'inetOrgPerson'))
            ->paging(2);

        $entries = new Entries();

        while ($paging->hasEntries()) {
            $entries->add(...$paging->getEntries()->toArray());
        }

        $this->assertCount(
            self::ENTRY_COUNT + self::SEEDED_PERSON_COUNT,
            $entries,
        );
    }

    public function testStreamYieldsAllMatchingResults(): void
    {
        $subject = $this->subject
            ->select('cn')
            ->andWhere(Filters::equal('objectClass', 'inetOrgPerson'));

        $count = 0;

        foreach ($subject->stream() as $result) {
            $this->assertInstanceOf(
                EntryResult::class,
                $result,
            );
            $this->assertNotNull($result->getEntry()->get('cn'));
            $count++;
        }

        $this->assertSame(
            self::ENTRY_COUNT + self::SEEDED_PERSON_COUNT,
            $count,
        );
    }

    public function testStreamYieldsResultsWithAccessibleMessageControls(): void
    {
        $subject = $this->subject
            ->select('cn')
            ->andWhere(Filters::equal('cn', 'user'));

        foreach ($subject->stream() as $result) {
            $this->assertNotNull($result->getEntry());
            $this->assertNotNull($result->getMessage());
        }
    }
}
