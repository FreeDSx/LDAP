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
use FreeDSx\Ldap\Control\ReadEntry\PostReadControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadControl;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortingResponseControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;

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

    /**
     * @return iterable<string, array{RequestInterface, Control}>
     */
    public static function inappropriateCriticalControls(): iterable
    {
        // RFC 4527 §3.1 leaves pre-read to the operations with a before image, which an add has not.
        yield 'pre-read on an add' => [
            Operations::add(Entry::create(
                'cn=ctl,dc=foo,dc=bar',
                ['objectClass' => 'inetOrgPerson', 'cn' => 'ctl', 'sn' => 'Ctl'],
            )),
            new PreReadControl('cn'),
        ];
        // RFC 4527 §3.2: a deleted entry has no after image, so post-read does not suit a delete.
        yield 'post-read on a delete' => [
            Operations::delete('cn=ctl,dc=foo,dc=bar'),
            new PostReadControl('cn'),
        ];
        yield 'pre-read on a compare' => [
            Operations::compare('cn=alice,ou=people,dc=foo,dc=bar', 'sn', 'Smith'),
            new PreReadControl('cn'),
        ];
        yield 'subtree delete on a modify' => [
            Operations::modify(
                'cn=alice,ou=people,dc=foo,dc=bar',
                Change::replace('description', 'ctl'),
            ),
            new Control(Control::OID_SUBTREE_DELETE),
        ];
    }

    /**
     * RFC 4511 §4.1.11: a control the operation does not take must fail it rather than be dropped.
     */
    #[DataProvider('inappropriateCriticalControls')]
    public function testACriticalControlTheOperationDoesNotTakeIsRefused(
        RequestInterface $request,
        Control $control,
    ): void {
        $this->authenticateAdmin();

        try {
            $this->ldapClient()->sendAndReceive(
                $request,
                $control->setCriticality(true),
            );
            self::fail('The critical control should have failed the operation.');
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

    /**
     * RFC 2891 §1.1: the rule the key names decides the order, not the one the attribute declares.
     */
    public function testSortControlHonorsTheRequestedOrderingRule(): void
    {
        $this->authenticateUser();

        self::assertSame(
            ['9', '10'],
            $this->sortedDescriptions(SortKey::ascending(
                'description',
                'integerOrderingMatch',
            )),
        );
    }

    /**
     * A type declaring no ORDERING rule still has the server's own order, so it is sortable.
     */
    public function testSortControlOrdersATypeWithNoOrderingRule(): void
    {
        $this->authenticateUser();

        // Ordered as numbers, '9' would come first.
        self::assertSame(
            ['10', '9'],
            $this->sortedDescriptions(SortKey::ascending('description')),
        );
    }

    /**
     * RFC 2891 §2: success promises the requested order, so a rule the stored order cannot provide is refused.
     */
    public function testSortControlRefusesARuleTheStoredOrderCannotProvide(): void
    {
        $this->authenticateUser();

        $response = $this->ldapClient()->send(
            Operations::search(Filters::present('uidNumber'), 'uidNumber')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
            new SortingControl(SortKey::ascending(
                'uidNumber',
                'caseIgnoreOrderingMatch',
            )),
        );

        $sortResponse = $response?->controls()->get(Control::OID_SORTING_RESPONSE);
        self::assertInstanceOf(
            SortingResponseControl::class,
            $sortResponse,
        );
        self::assertSame(
            ResultCode::INAPPROPRIATE_MATCHING,
            $sortResponse->getResult(),
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

    /**
     * The description values the seed carries, in the order the sort key put them.
     *
     * @return list<string>
     */
    private function sortedDescriptions(SortKey $sortKey): array
    {
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('description'), 'description')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
            new SortingControl($sortKey),
        );

        return array_values(array_map(
            static fn(Entry $entry): string => $entry->get('description')?->firstValue() ?? '',
            $entries->toArray(),
        ));
    }
}
