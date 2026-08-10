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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * Read operations: scope, filter evaluation, projection, compare, and search limits.
 */
trait QueryTestsTrait
{
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
}
