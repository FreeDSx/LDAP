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
