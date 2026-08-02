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

namespace Tests\Integration\FreeDSx\Ldap\Storage;

use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

class LdapBackendStorageTest extends ServerTestCase
{
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            static::storageExtraArgs(),
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-backend-storage');

        parent::setUp();
    }

    public function testBindWithCorrectCredentials(): void
    {
        // No exception thrown — bind succeeded; verify the session is usable
        $this->authenticateUser();

        self::assertTrue(
            $this->ldapClient()->compare('cn=user,dc=foo,dc=bar', 'cn', 'user'),
        );
    }

    public function testBindWithWrongCredentials(): void
    {
        $this->expectException(BindException::class);

        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', 'wrongpassword');
    }

    public function testBindWithUnknownDn(): void
    {
        $this->expectException(BindException::class);

        $this->ldapClient()->bind('cn=nobody,dc=foo,dc=bar', '12345');
    }

    public function testSearchBaseObjectReturnsBaseEntry(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useBaseScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame('dc=foo,dc=bar', $entries->first()?->getDn()->toString());
    }

    public function testSearchSingleLevelReturnsDirectChildrenOnly(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useSingleLevelScope(),
        );

        self::assertCount(
            5,
            $entries,
        );
    }

    public function testSearchSubtreeWithFilterReturnsMatchingEntry(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'cn=alice,ou=people,dc=foo,dc=bar',
            $entries->first()?->getDn()->toString(),
        );
    }

    public function testSearchReturnsAttributeValues(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        $alice = $entries->first();
        self::assertNotNull($alice);
        self::assertSame(['Smith'], $alice->get('sn')?->getValues());
    }

    public function testSearchTypesOnlyReturnsAttributeNamesWithoutValues(): void
    {
        $this->authenticateUser();

        $request = Operations::search(Filters::equal('cn', 'alice'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();
        $request->setAttributesOnly(true);

        $entries = $this->ldapClient()->search($request);

        $alice = $entries->first();
        self::assertNotNull($alice);
        // sn attribute should be present but with no values
        $sn = $alice->get('sn');
        self::assertNotNull($sn);
        self::assertEmpty($sn->getValues());
    }

    public function testSearchWithNoMatchReturnsEmptyResult(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'nobody'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(0, $entries);
    }

    public function testUserPasswordIsNotReturnedUnderTheDefaultAcl(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'user'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->setAttributes('cn', 'userPassword'),
        );

        // The shipped default marks userPassword confidential and grants nobody access to it.
        $user = $entries->first();
        self::assertNotNull($user);
        self::assertNull($user->get('userPassword'));
    }

    public function testFilteringOnUserPasswordMatchesNothingUnderTheDefaultAcl(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('userPassword', '{SHA}' . base64_encode(sha1('12345', true))))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            0,
            $entries,
        );
    }

    public function testNegatingAWithheldAssertionMatchesEveryEntry(): void
    {
        $this->authenticateUser();

        $all = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        // Withheld reads as absent, so negating it holds for every entry rather than none.
        $negated = $this->ldapClient()->search(
            Operations::search(Filters::not(Filters::equal('userPassword', 'anything')))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            count($all),
            $negated,
        );
    }

    public function testAConjunctionWithAWithheldAssertionMatchesNothing(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::and(
                Filters::equal('cn', 'user'),
                Filters::equal('userPassword', 'anything'),
            ))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            0,
            $entries,
        );
    }

    public function testSearchFilterAppliesTheSchemaDeclaredMatchingRule(): void
    {
        $this->authenticateUser();

        $exact = $this->ldapClient()->search(
            Operations::search(Filters::equal('employeeNumber', 'A1b2C3'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        // The schema matches employeeNumber case-exactly. Storage post-filters results itself, so a case-folded
        // value matching here would mean that path evaluated without the schema.
        $caseFolded = $this->ldapClient()->search(
            Operations::search(Filters::equal('employeeNumber', 'a1b2c3'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            1,
            $exact,
        );
        self::assertCount(
            0,
            $caseFolded,
        );
    }

    public function testAddStoresEntry(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=charlie,dc=foo,dc=bar',
            ['cn' => 'charlie', 'sn' => 'Charlie', 'objectClass' => 'inetOrgPerson'],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'charlie'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        self::assertCount(1, $entries);
    }

    public function testAddPreservesAttributeOptionsOnRoundTrip(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=tagged,dc=foo,dc=bar',
            [
                'cn' => 'tagged',
                'cn;lang-en' => 'Tagged EN',
                'sn' => 'Tag',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn;lang-en', 'Tagged EN'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        $tagged = $entries->first();
        self::assertNotNull($tagged);
        self::assertSame(
            ['Tagged EN'],
            $tagged->get(new Attribute('cn;lang-en'), true)?->getValues(),
        );
        self::assertSame(
            ['tagged'],
            $tagged->get(new Attribute('cn'), true)?->getValues(),
        );
    }

    public function testInexactFilterOnUnrequestedAttributeStillMatchesAndProjects(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=hazard,dc=foo,dc=bar',
            [
                'cn' => 'hazard',
                'sn' => 'Smithers',
                'mail' => 'hazard@foo.bar',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        // Substring is inexact: SQL yields candidates and PHP re-evaluates (sn) on the hydrated entry, so storage must
        // materialize sn (filter-referenced) even though only cn was requested; projection then drops it.
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::contains('sn', 'mither'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->select('cn'),
        );

        $entry = $entries->first();
        self::assertNotNull($entry);
        self::assertSame(
            'cn=hazard,dc=foo,dc=bar',
            $entry->getDn()->toString(),
        );
        self::assertSame(
            ['hazard'],
            $entry->get(new Attribute('cn'), true)?->getValues(),
        );
        self::assertNull($entry->get(new Attribute('sn'), true));
    }

    public function testNoAttributesRequestStillMatchesAnInexactFilter(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=noattr,dc=foo,dc=bar',
            [
                'cn' => 'noattr',
                'sn' => 'Jones',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::contains('sn', 'one'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->select('1.1'),
        );

        $entry = $entries->first();
        self::assertNotNull($entry);
        self::assertSame(
            'cn=noattr,dc=foo,dc=bar',
            $entry->getDn()->toString(),
        );
        self::assertCount(
            0,
            $entry->getAttributes(),
        );
    }

    public function testAddDuplicateDnFails(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=user,dc=foo,dc=bar',
            ['cn' => 'user', 'sn' => 'User', 'objectClass' => 'inetOrgPerson'],
        ));
    }

    public function testDeleteRemovesEntry(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->delete('cn=alice,ou=people,dc=foo,dc=bar');

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        self::assertCount(0, $entries);
    }

    public function testDeleteNonLeafEntryFails(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NOT_ALLOWED_ON_NON_LEAF);

        // ou=people still has cn=alice as a child
        $this->ldapClient()->delete('ou=people,dc=foo,dc=bar');
    }

    public function testModifyReplacesAttributeValue(): void
    {
        $this->authenticateAdmin();

        $entry = Entry::fromArray('cn=alice,ou=people,dc=foo,dc=bar');
        $entry->set('sn', 'Jones');
        $this->ldapClient()->update($entry);

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('sn', 'Jones'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        self::assertCount(1, $entries);
        self::assertSame(['Jones'], $entries->first()?->get('sn')?->getValues());
    }

    public function testRenameChangesRdn(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->rename('cn=alice,ou=people,dc=foo,dc=bar', 'cn=bob', true);

        $found = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'bob'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        self::assertCount(1, $found);
        self::assertSame('cn=bob,ou=people,dc=foo,dc=bar', $found->first()?->getDn()->toString());

        // Old DN should no longer exist
        $notFound = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        self::assertCount(0, $notFound);
    }

    public function testCompareReturnsTrueForMatchingValue(): void
    {
        $this->authenticateUser();

        $result = $this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'sn',
            'Smith',
        );

        self::assertTrue($result);
    }

    public function testCompareReturnsFalseForNonMatchingValue(): void
    {
        $this->authenticateUser();

        $result = $this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'sn',
            'Jones',
        );

        self::assertFalse($result);
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
            7,
            $allEntries,
        );
    }

    public function testPagingWithholdsConfidentialAttributes(): void
    {
        $this->authenticateUser();

        // Paging strips results on its own loop, separate from the one a plain search uses.
        $search = Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope()
            ->setAttributes('cn', 'userPassword');

        $paging = $this->ldapClient()->paging($search, 2);
        $withPassword = 0;

        while ($paging->hasEntries()) {
            foreach ($paging->getEntries() as $entry) {
                if ($entry->get('userPassword') !== null) {
                    $withPassword++;
                }
            }
        }

        self::assertSame(
            0,
            $withPassword,
        );
    }

    public function testPagingOnAWithheldFilterReturnsNothing(): void
    {
        $this->authenticateUser();

        $search = Operations::search(Filters::equal('userPassword', 'anything'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        $paging = $this->ldapClient()->paging($search, 2);
        $found = 0;

        while ($paging->hasEntries()) {
            $found += count($paging->getEntries());
        }

        self::assertSame(
            0,
            $found,
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

    public function testSubstringStartsWithMatches(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::startsWith('cn', 'al'))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'cn=alice,ou=people,dc=foo,dc=bar',
            $entries->first()?->getDn()->toString(),
        );
    }

    public function testSubstringContainsMatches(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::contains('cn', 'lic'))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'cn=alice,ou=people,dc=foo,dc=bar',
            $entries->first()?->getDn()->toString(),
        );
    }

    public function testSubstringEndsWithMatches(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::endsWith('cn', 'ice'))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'cn=alice,ou=people,dc=foo,dc=bar',
            $entries->first()?->getDn()->toString(),
        );
    }

    public function testGteAsciiExcludesLowerValue(): void
    {
        $this->authenticateUser();

        // Scope to ou=people so cn=user (which would match cn >= 'alicf') is excluded.
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::gte('cn', 'alicf'))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        // 'alice' < 'alicf' lexicographically
        self::assertCount(0, $entries);
    }

    public function testLteAsciiIncludesMatchingValue(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::and(
                Filters::present('cn'),
                Filters::lte('cn', 'alice'),
            ))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'cn=alice,ou=people,dc=foo,dc=bar',
            $entries->first()?->getDn()->toString(),
        );
    }

    /**
     * uidNumber declares the INTEGER syntax, so '99' is below '100' rather than above it bytewise.
     */
    public function testGteOnAnIntegerAttributeOrdersNumerically(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::gte('uidNumber', '100'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(0, $entries);
    }

    /**
     * Bytewise, '99' would sort above '100' and be excluded.
     */
    public function testLteOnAnIntegerAttributeOrdersNumerically(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::lte('uidNumber', '100'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'cn=alice,ou=people,dc=foo,dc=bar',
            $entries->first()?->getDn()->toString(),
        );
    }

    public function testNotEqualityExcludesMatches(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::and(
                Filters::present('cn'),
                Filters::not(Filters::equal('cn', 'alice')),
            ))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        // Under ou=people only alice exists in the seed; NOT-equal alice leaves zero matches.
        self::assertCount(0, $entries);
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

    public function testInexactSearchTripsLookthroughLimit(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--seed-entries=10',
                '--max-search-lookthrough=3',
            ],
        );
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->ldapClient()->search(
            Operations::search(Filters::endsWith('cn', 'zzz'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
    }

    public function testSearchDeclinesAliasDereferencing(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', static::storageExtraArgs());
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray('cn=ref,dc=foo,dc=bar', [
            'objectClass' => ['top', 'alias', 'extensibleObject'],
            'cn' => 'ref',
            'aliasedObjectName' => 'cn=user,dc=foo,dc=bar',
        ]));

        $neverRequest = Operations::search(Filters::equal('cn', 'ref'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        self::assertCount(
            1,
            $this->ldapClient()->search($neverRequest),
        );

        $derefRequest = Operations::search(Filters::equal('cn', 'ref'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope()
            ->setDereferenceAliases(SearchRequest::DEREF_ALWAYS);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ALIAS_DEREFERENCING_PROBLEM);
        $this->ldapClient()->search($derefRequest);
    }

    /**
     * Hook for subclasses to route the shared server through a different backend.
     *
     * @return list<string>
     */
    protected static function storageExtraArgs(): array
    {
        return [];
    }
}
