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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortingResponseControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * Search controls the backend participates in: paged results and server side sorting.
 */
trait ControlTestsTrait
{
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

    public function testACriticalSortThatCannotBePerformedFailsTheSearch(): void
    {
        $this->authenticateUser();

        try {
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
                (new SortingControl(SortKey::ascending('bogusAttr')))->setCriticality(true),
            );
            self::fail('The critical sort should have failed the search.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
                $e->getCode(),
            );
        }
    }

    public function testACriticalSortThatCannotBePerformedFailsAPagedSearch(): void
    {
        $this->authenticateUser();

        $paging = $this->ldapClient()
            ->paging(
                Operations::search(Filters::present('objectClass'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
                2,
            )
            ->useControls((new SortingControl(SortKey::ascending('bogusAttr')))->setCriticality(true));

        try {
            $entries = $paging->getEntries();
            self::fail(sprintf(
                'The critical sort should have failed the paged search, got %d entries.',
                count($entries),
            ));
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
                $e->getCode(),
            );
        }
    }

    public function testANonCriticalSortThatCannotBePerformedStillReturnsPagedEntries(): void
    {
        $this->authenticateUser();

        $paging = $this->ldapClient()
            ->paging(
                Operations::search(Filters::present('objectClass'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
                2,
            )
            ->useControls(new SortingControl(SortKey::ascending('bogusAttr')));

        self::assertCount(
            2,
            $paging->getEntries(),
        );
    }

    public function testANonCriticalSortThatCannotBePerformedStillReturnsEntries(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
            new SortingControl(SortKey::ascending('bogusAttr')),
        );

        self::assertCount(
            8,
            $entries,
        );
    }

    public function testARepeatedSortKeyAttributeIsRefusedInTheSortResult(): void
    {
        $this->authenticateUser();

        $response = $this->ldapClient()->send(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
            new SortingControl(
                SortKey::ascending('sn'),
                SortKey::descending('sn'),
            ),
        );

        $sortResponse = $response?->controls()->get(Control::OID_SORTING_RESPONSE);
        self::assertInstanceOf(
            SortingResponseControl::class,
            $sortResponse,
        );
        self::assertSame(
            ResultCode::UNWILLING_TO_PERFORM,
            $sortResponse->getResult(),
        );
    }

    public function testAMalformedControlValueIsAnsweredWithoutEndingTheSession(): void
    {
        $this->authenticateUser();

        $search = Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        try {
            $this->ldapClient()->search(
                $search,
                new Control(
                    Control::OID_PAGING,
                    false,
                    'not-a-paging-control',
                ),
            );
            self::fail('The malformed control value should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::PROTOCOL_ERROR,
                $e->getCode(),
            );
        }

        // The same connection must still serve requests, which is the whole point of answering rather than closing.
        self::assertCount(
            8,
            $this->ldapClient()->search($search),
        );
    }

    public function testSortControlAscendingOrdersResults(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('sn'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
            new SortingControl(SortKey::ascending('sn')),
        );

        $sns = array_map(
            static fn(Entry $e): string => $e->get('sn')?->getValues()[0] ?? '',
            $entries->toArray(),
        );

        // Seed: cn=user and cn=admin (sn=Admin), cn=alice (sn=Smith). Admin < Smith ascending.
        self::assertSame(
            ['Admin', 'Admin', 'Smith'],
            $sns,
        );
    }

    public function testSortControlDescendingOrdersResults(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('sn'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
            new SortingControl(SortKey::descending('sn')),
        );

        $sns = array_map(
            static fn(Entry $e): string => $e->get('sn')?->getValues()[0] ?? '',
            $entries->toArray(),
        );

        // Seed: cn=user and cn=admin (sn=Admin), cn=alice (sn=Smith). Smith > Admin descending.
        self::assertSame(
            ['Smith', 'Admin', 'Admin'],
            $sns,
        );
    }

    public function testSortControlOrdersAnIntegerAttributeNumerically(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('uidNumber'), 'uidNumber')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
            new SortingControl(SortKey::ascending('uidNumber')),
        );

        $values = array_map(
            static fn(Entry $e): string => $e->get('uidNumber')?->firstValue() ?? '',
            $entries->toArray(),
        );

        // Ordered as text, '100' would come first.
        self::assertSame(
            ['99', '100'],
            $values,
        );
    }

    public function testSortControlPlacesMissingAttributeLastWhenAscending(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('cn'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
            new SortingControl(SortKey::ascending('sn')),
        )->toArray();

        // More than one seed entry lacks 'sn', so assert the ordering rather than which of them sorts last.
        self::assertNull($entries[count($entries) - 1]->get('sn'));
        self::assertNotNull($entries[0]->get('sn'));
    }

    public function testSortControlPlacesMissingAttributeFirstWhenDescending(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('cn'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
            new SortingControl(SortKey::descending('sn')),
        )->toArray();

        // More than one seed entry lacks 'sn', so assert the ordering rather than which of them sorts first.
        self::assertNull($entries[0]->get('sn'));
        self::assertNotNull($entries[count($entries) - 1]->get('sn'));
    }
}
