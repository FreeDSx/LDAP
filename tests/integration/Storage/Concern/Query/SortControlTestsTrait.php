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
 * The server side sort control (RFC 2891): the order it produces, and how it answers a sort it cannot perform.
 */
trait SortControlTestsTrait
{
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

    public function testASortKeyOnAWithheldAttributeDoesNotOrderByItsHiddenValue(): void
    {
        $this->authenticateAdmin();
        // Distinct passwords, created in an order unrelated to how their hashes sort.
        $passwords = ['sort-leak-1' => 'mango', 'sort-leak-2' => 'apple', 'sort-leak-3' => 'cherry'];
        foreach ($passwords as $cn => $password) {
            $this->ldapClient()->create(Entry::fromArray("cn={$cn},ou=people,dc=foo,dc=bar", [
                'objectClass' => ['inetOrgPerson'],
                'cn' => [$cn],
                'sn' => ['SortLeakProbe'],
                'userPassword' => ['{SHA}' . base64_encode(sha1($password, true))],
            ]));
        }

        $this->authenticateUser();
        $order = function (bool $descending): array {
            $entries = $this->ldapClient()->search(
                Operations::search(Filters::equal('sn', 'SortLeakProbe'), 'cn', 'userPassword')
                    ->base('ou=people,dc=foo,dc=bar')
                    ->useSubtreeScope(),
                new SortingControl(new SortKey('userPassword', $descending)),
            );
            $cns = [];
            $visible = 0;
            foreach ($entries as $entry) {
                $cns[] = $entry->get('cn')?->firstValue();
                $visible += $entry->get('userPassword') === null ? 0 : 1;
            }

            return ['cns' => $cns, 'visible' => $visible];
        };

        $ascending = $order(false);
        $descending = $order(true);

        $this->authenticateAdmin();
        foreach (array_keys($passwords) as $cn) {
            $this->ldapClient()->delete("cn={$cn},ou=people,dc=foo,dc=bar");
        }

        // The withheld key has no effect, so reversing it cannot reorder the result.
        self::assertSame(
            $ascending['cns'],
            $descending['cns'],
        );
        self::assertSame(
            0,
            $ascending['visible'],
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

    public function testSortControlOrdersByAKeySpelledWithAnAlias(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('sn'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
            new SortingControl(SortKey::descending('surname')),
        );

        $sns = array_map(
            static fn(Entry $e): string => $e->get('sn')?->getValues()[0] ?? '',
            $entries->toArray(),
        );

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
