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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query;

use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * The paged results control (RFC 2696): walking a search a page at a time, and the limits each page is held to.
 */
trait PagingControlTestsTrait
{
    public function testTheLookthroughLimitBoundsThePageRatherThanEachSliceOfIt(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--seed-entries=10',
                '--max-search-lookthrough=12',
            ],
        );
        $this->authenticateUser();

        $paging = $this->ldapClient()->paging(
            Operations::search(Filters::not(Filters::contains('sn', 'Seeded')))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
            10,
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $paging->getEntries();
    }

    public function testAFullPageWithNoFurtherMatchIsNotASizeLimitOverflow(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--seed-entries=10',
            ],
        );
        $this->authenticateUser();

        $paging = $this->ldapClient()->paging(
            Operations::search(Filters::not(Filters::contains('sn', 'Seeded')))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->setSizeLimit(8),
            8,
        );

        $entries = [];

        while ($paging->hasEntries()) {
            foreach ($paging->getEntries() as $entry) {
                $entries[] = $entry->getDn()->toString();
            }
        }

        self::assertCount(
            8,
            $entries,
        );
    }

    public function testAFullPageWithAFurtherMatchIsASizeLimitOverflow(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--seed-entries=10',
            ],
        );
        $this->authenticateUser();

        $paging = $this->ldapClient()->paging(
            Operations::search(Filters::not(Filters::contains('sn', 'Seeded')))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->setSizeLimit(4),
            4,
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::SIZE_LIMIT_EXCEEDED);

        $paging->getEntries();
    }

    public function testPagingReturnsAllEntriesAcrossMultiplePages(): void
    {
        $this->authenticateUser();

        $search = Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        $paging = $this->ldapClient()->paging($search, 2);

        $allEntries = [];

        while ($paging->hasEntries()) {
            foreach ($paging->getEntries() as $entry) {
                $allEntries[] = $entry->getDn()->toString();
            }
        }

        self::assertCount(
            8,
            $allEntries,
        );
    }

    /**
     * The base entry and ou=people are in scope but carry no cn, so both are read as candidates and dropped after.
     */
    public function testNoPageExceedsTheRequestedSizeWhenEntriesAreDroppedAfterTheRead(): void
    {
        $this->authenticateUser();

        foreach ([2, 3, 4] as $pageSize) {
            $paging = $this->ldapClient()->paging(
                Operations::search(Filters::present('cn'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
                $pageSize,
            );

            $sizes = [];
            $total = 0;
            $largest = 0;
            while ($paging->hasEntries()) {
                $count = count($paging->getEntries());
                $sizes[] = $count;
                $total += $count;
                $largest = max($largest, $count);
            }

            self::assertLessThanOrEqual(
                $pageSize,
                $largest,
                sprintf(
                    'A page of at most %d was asked for, but one arrived with %d: pages were [%s].',
                    $pageSize,
                    $largest,
                    implode(',', $sizes),
                ),
            );
            self::assertSame(
                6,
                $total,
                'Bounding the page must not lose or repeat an entry.',
            );
        }
    }

    public function testSortedPagingReturnsEveryEntryOnceInOrder(): void
    {
        $this->authenticateUser();

        $search = Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        $paging = $this->ldapClient()
            ->paging($search, 3)
            ->useControls(new SortingControl(SortKey::ascending('cn')));

        $dns = [];

        while ($paging->hasEntries()) {
            foreach ($paging->getEntries() as $entry) {
                $dns[] = $entry->getDn()->toString();
            }
        }

        self::assertSame(
            array_values(array_unique($dns)),
            $dns,
            'A sorted walk must not repeat an entry it already delivered.',
        );
        self::assertCount(
            8,
            $dns,
            'A sorted walk must hand over every entry.',
        );
    }

    /**
     * RFC 2696 §3 promises no snapshot, so the walk need only stay coherent: end, and repeat nothing.
     */
    public function testPagingSurvivesWritesLandingBetweenPages(): void
    {
        $this->authenticateAdmin();

        $search = Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        $paging = $this->ldapClient()->paging($search, 2);
        $dns = [];
        $wrote = false;

        while ($paging->hasEntries()) {
            foreach ($paging->getEntries() as $entry) {
                $dns[] = $entry->getDn()->toString();
            }

            if (!$wrote) {
                $wrote = true;
                $this->ldapClient()->create(Entry::fromArray('cn=mid-walk,dc=foo,dc=bar', [
                    'objectClass' => ['top', 'inetOrgPerson'],
                    'cn' => 'mid-walk',
                    'sn' => 'Added',
                ]));
            }
        }

        // Dropped before asserting, so a sibling counting the fixture does not inherit it.
        $this->ldapClient()->delete('cn=mid-walk,dc=foo,dc=bar');

        self::assertSame(
            array_values(array_unique($dns)),
            $dns,
            'A walk must not hand over an entry it already delivered.',
        );
        self::assertGreaterThanOrEqual(
            8,
            count($dns),
            'Entries present before the write must still be delivered.',
        );
    }

    public function testPagingCanBeAbandoned(): void
    {
        $this->authenticateUser();

        $search = Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        $paging = $this->ldapClient()->paging($search, 1);

        // Get the first page only, then abandon
        $paging->getEntries();
        $paging->end();

        // After abandonment, hasEntries() must return false
        self::assertFalse($paging->hasEntries());
    }

    /**
     * RFC 2696 3 prescribes this when a client resumes a paged search the server aged out.
     */
    public function testResumingAnAgedOutPagingSessionIsUnwillingToPerform(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--max-paging-sessions=1',
            ],
        );
        $this->authenticateUser();

        $search = Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        $first = $this->ldapClient()->paging($search, 1);
        $first->getEntries();

        // Starting a second session at the cap ages the first one out.
        $second = $this->ldapClient()->paging($search, 1);
        $second->getEntries();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $first->getEntries();
    }
}
