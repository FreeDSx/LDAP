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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * Single filter items answered by the type's own equality, substring, and ordering rules.
 */
trait FilterMatchingTestsTrait
{
    public function testAnUnrecognizedMatchingRuleDoesNotFailTheWholeSearch(): void
    {
        $this->authenticateUser();

        // The bad assertion is Undefined, so the disjunction still returns what its other branch matches.
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::or(
                Filters::equal('cn', 'alice'),
                Filters::extensible('cn', 'alice', '9.9.9.9', false),
            ))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            1,
            $entries,
        );
    }

    public function testSearchFilterAppliesTheSchemaDeclaredMatchingRule(): void
    {
        $this->authenticateUser();

        $exact = $this->ldapClient()->search(
            Operations::search(Filters::equal('labeledURI', 'A1b2C3'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        // The schema matches labeledURI case-exactly. Storage post-filters results itself, so a case-folded
        // value matching here would mean that path evaluated without the schema.
        $caseFolded = $this->ldapClient()->search(
            Operations::search(Filters::equal('labeledURI', 'a1b2c3'))
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

    public function testAnUpperCaseEntryUuidMatchesInAFilterAndACompare(): void
    {
        $this->authenticateUser();

        $alice = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'), 'entryUUID')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        )->first();
        $uuid = strtoupper((string) $alice?->get('entryUUID')?->firstValue());

        $matched = $this->ldapClient()->search(
            Operations::search(Filters::equal('entryUUID', $uuid))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            ['cn=alice,ou=people,dc=foo,dc=bar'],
            array_map(
                static fn(Entry $entry): string => $entry->getDn()->toString(),
                $matched->toArray(),
            ),
        );
        self::assertTrue($this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'entryUUID',
            $uuid,
        ));
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

    public function testSubstringStartsWithIgnoresCaseUnderACaseIgnoreRule(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::startsWith('cn', 'AL'))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            ['cn=alice,ou=people,dc=foo,dc=bar'],
            array_map(
                static fn(Entry $entry): string => $entry->getDn()->toString(),
                $entries->toArray(),
            ),
        );
    }

    public function testSubstringStartsWithTreatsLikeWildcardsLiterally(): void
    {
        $this->authenticateUser();

        $underscore = $this->ldapClient()->search(
            Operations::search(Filters::startsWith('cn', 'a_'))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        $percent = $this->ldapClient()->search(
            Operations::search(Filters::startsWith('cn', 'a%'))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            0,
            $underscore,
        );
        self::assertCount(
            0,
            $percent,
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
     * uidNumber declares the INTEGER syntax, so 99 is below 100 rather than above it bytewise.
     */
    public function testGteOnAnIntegerAttributeOrdersNumerically(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::gte('uidNumber', '100'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        // Bytewise, '99' would also be at or above '100'.
        self::assertCount(1, $entries);
        self::assertSame(
            'cn=Smith\\, John,dc=foo,dc=bar',
            $entries->first()?->getDn()->toString(),
        );
    }

    public function testLteOnAnIntegerAttributeOrdersNumerically(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::lte('uidNumber', '100'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        // Bytewise, '99' would sort above '100' and be excluded.
        self::assertCount(2, $entries);
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
}
