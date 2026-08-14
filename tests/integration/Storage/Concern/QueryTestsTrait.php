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
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Read operations: scope, filter evaluation, projection, compare, and search limits.
 */
trait QueryTestsTrait
{
    /**
     * RFC 4511 4.5.1 evaluation, driven over a real connection so every assertion travels as BER.
     *
     * The seed holds seven entries; only cn=alice carries uidNumber, mail and employeeNumber. Each backend runs these,
     * since the PDO adapters translate filters to SQL and only re-check inexact results in PHP.
     *
     * @return iterable<string, array{FilterInterface, int}>
     */
    public static function filterProvider(): iterable
    {
        yield 'present' => [
            Filters::present('uidNumber'),
            2,
        ];
        yield 'approximate' => [
            Filters::approximate('cn', 'alice'),
            1,
        ];
        yield 'and' => [
            Filters::and(
                Filters::equal('cn', 'alice'),
                Filters::present('sn'),
            ),
            1,
        ];
        yield 'or' => [
            Filters::or(
                Filters::equal('cn', 'alice'),
                Filters::equal('cn', 'nosn'),
            ),
            2,
        ];
        yield 'not' => [
            Filters::not(Filters::equal('cn', 'alice')),
            7,
        ];

        // RFC 4526.
        yield 'absolute true' => [
            Filters::and(),
            8,
        ];
        yield 'absolute false' => [
            Filters::or(),
            0,
        ];

        yield 'a non numeric assertion cannot match an integer' => [
            Filters::equal('uidNumber', 'abc'),
            0,
        ];
        // Casting to an integer would read this as the stored value and match it.
        yield 'an integer assertion with trailing text matches nothing' => [
            Filters::equal('uidNumber', '99abc'),
            0,
        ];
        // RFC 4517 3.3.16 forbids a leading zero, so the assertion value is invalid and the item is Undefined.
        yield 'an integer assertion with a leading zero is undefined' => [
            Filters::equal('uidNumber', '099'),
            0,
        ];
        yield 'a negated integer assertion with a leading zero is still undefined' => [
            Filters::not(Filters::equal('uidNumber', '099')),
            0,
        ];

        // RFC 4511 4.5.1.7: an assertion on an unrecognized attribute type is Undefined, and NOT of Undefined stays
        // Undefined, so no entry may be returned. A present filter on a known type is False, never Undefined.
        yield 'negating an unrecognized attribute type matches nothing' => [
            Filters::not(Filters::present('shoeSize')),
            0,
        ];
        yield 'negating an absent but defined attribute matches everything' => [
            Filters::not(Filters::present('telephoneNumber')),
            8,
        ];
        yield 'negating a value assertion on an unrecognized type matches nothing' => [
            Filters::not(Filters::equal('shoeSize', '12')),
            0,
        ];
        yield 'negating a value assertion on an absent but defined attribute' => [
            Filters::not(Filters::equal('telephoneNumber', '555')),
            8,
        ];
        yield 'negating a conjunction' => [
            Filters::not(Filters::and(
                Filters::equal('cn', 'alice'),
                Filters::present('sn'),
            )),
            7,
        ];
        // A conjunction is false as soon as one branch is false, so every entry failing the recognized branch is
        // negated to true. Only the entry that satisfies it is left Undefined by the branch that cannot be resolved.
        yield 'negating a conjunction holding an unrecognized type' => [
            Filters::not(Filters::and(
                Filters::equal('cn', 'alice'),
                Filters::equal('shoeSize', '12'),
            )),
            7,
        ];

        // RFC 4512 2.5.2: an assertion on the base type covers its tagged variants and its subtypes.
        yield 'the base type matches a value held under an option' => [
            Filters::equal('mail', 'alice-en@foo.bar'),
            1,
        ];
        yield 'a supertype matches a value held by its subtype' => [
            Filters::equal('name', 'alice'),
            1,
        ];

        // RFC 4511 4.5.1.7.7.
        yield 'extensible with an explicit matching rule' => [
            Filters::extensible('cn', 'ALICE', '2.5.13.2', false),
            1,
        ];
        yield 'extensible without a rule uses the type EQUALITY' => [
            Filters::extensible('employeeNumber', 'A1b2C3', null, false),
            1,
        ];
        yield 'extensible without a rule respects a case exact EQUALITY' => [
            Filters::extensible('employeeNumber', 'a1b2c3', null, false),
            0,
        ];
        yield 'extensible with an unrecognized rule is Undefined' => [
            Filters::extensible('cn', 'alice', '9.9.9.9', false),
            0,
        ];
        yield 'extensible against the DN' => [
            Filters::extensible('cn', 'alice', null, true),
            1,
        ];
        // The RDN stores this value escaped, but the assertion is against the value itself.
        yield 'extensible against a DN whose value needs escaping' => [
            Filters::extensible('cn', 'Smith, John', null, true),
            1,
        ];

        // RFC 4518 appendix B: a space at the edge of a fragment stays significant, so these must not match a value
        // holding no space there. Collapsing and trimming both sides alike would wrongly match all three.
        yield 'an initial and final space cannot match a value without them' => [
            Filters::startsWith('cn', 'al ')->setEndsWith(' ice'),
            0,
        ];
        yield 'a leading space in an any fragment is significant' => [
            Filters::contains('cn', ' alice '),
            0,
        ];
        yield 'the same assertion split across fragments agrees' => [
            Filters::startsWith('cn', ' ')->setContains('alice')->setEndsWith(' '),
            0,
        ];
        yield 'a fragment spanning a space matches a value holding one' => [
            Filters::contains('cn', 'Smith, John'),
            1,
        ];

        // No approximate rule is implemented, so it must answer as the type's equality rule does.
        yield 'approximate on a case exact type rejects a case difference' => [
            Filters::approximate('employeeNumber', 'a1b2c3'),
            0,
        ];
        yield 'approximate on a case exact type accepts the exact value' => [
            Filters::approximate('employeeNumber', 'A1b2C3'),
            1,
        ];

        // An assertion value the type's syntax rejects is Undefined, which is excluded under negation as well. The
        // valid-but-unmatched pairs are the control: those negate to every entry, the invalid ones to none.
        yield 'an assertion value the syntax rejects matches nothing' => [
            Filters::equal('member', '%%%'),
            0,
        ];
        yield 'a negated assertion value the syntax rejects still matches nothing' => [
            Filters::not(Filters::equal('member', '%%%')),
            0,
        ];
        yield 'a valid assertion matching no entry matches nothing' => [
            Filters::equal('member', 'cn=nobody,dc=foo,dc=bar'),
            0,
        ];
        yield 'a negated valid assertion matching no entry matches every entry' => [
            Filters::not(Filters::equal('member', 'cn=nobody,dc=foo,dc=bar')),
            8,
        ];
        yield 'an ordered assertion the syntax rejects matches nothing' => [
            Filters::greaterThanOrEqual('member', '%%%'),
            0,
        ];
        yield 'a negated ordered assertion the syntax rejects matches nothing' => [
            Filters::not(Filters::greaterThanOrEqual('member', '%%%')),
            0,
        ];
        // RFC 4511 4.5.1.7: a substring item applies the type's SUBSTR rule, so a type declaring none is Undefined
        // for every entry, negated or not. The pairs below are the control: types that do declare one still answer.
        yield 'a substring on a type with no substring rule matches nothing' => [
            Filters::startsWith(
                'member',
                'cn=user,',
            ),
            0,
        ];
        yield 'a negated substring on a type with no substring rule still matches nothing' => [
            Filters::not(
                Filters::startsWith(
                    'member',
                    'cn=user,',
                ),
            ),
            0,
        ];
        yield 'a substring on an integer type matches nothing' => [
            Filters::startsWith(
                'uidNumber',
                '9',
            ),
            0,
        ];
        yield 'a negated substring on an integer type still matches nothing' => [
            Filters::not(
                Filters::startsWith(
                    'uidNumber',
                    '9',
                ),
            ),
            0,
        ];
        yield 'a substring on entryDN matches nothing' => [
            Filters::endsWith(
                'entryDN',
                'dc=foo,dc=bar',
            ),
            0,
        ];
        yield 'a substring on a type declaring a substring rule matches' => [
            Filters::startsWith(
                'cn',
                'al',
            ),
            1,
        ];
        yield 'a substring on an ia5 type declaring a substring rule matches' => [
            Filters::endsWith(
                'mail',
                '@foo.bar',
            ),
            1,
        ];
        yield 'a negated substring on a type declaring a substring rule matches the rest' => [
            Filters::not(
                Filters::startsWith(
                    'cn',
                    'al',
                ),
            ),
            7,
        ];

        // RFC 5020: entryDN is derived on read, so it must match without having been requested or stored.
        yield 'entryDN matches the entry it names' => [
            Filters::equal(
                'entryDN',
                'cn=alice,ou=people,dc=foo,dc=bar',
            ),
            1,
        ];
        yield 'entryDN compares as a dn rather than a string' => [
            Filters::equal(
                'entryDN',
                'CN=alice,OU=people,DC=foo,DC=bar',
            ),
            1,
        ];
        yield 'entryDN matches an escaped rdn by its unescaped value' => [
            Filters::equal(
                'entryDN',
                'cn=Smith\, John,dc=foo,dc=bar',
            ),
            1,
        ];
        yield 'entryDN matches nothing for an absent dn' => [
            Filters::equal(
                'entryDN',
                'cn=nobody,dc=foo,dc=bar',
            ),
            0,
        ];
        yield 'entryDN is present on every entry' => [
            Filters::present('entryDN'),
            8,
        ];

        // cn=alice stores shoeSize, which the configured schema does not define. Every assertion on it is Undefined
        // regardless of that stored value, and Undefined is excluded under negation too (RFC 4511 4.5.1.7).
        yield 'an unrecognized type an entry stores is undefined' => [
            Filters::equal(
                'shoeSize',
                '12',
            ),
            0,
        ];
        yield 'a negated unrecognized type an entry stores is still undefined' => [
            Filters::not(
                Filters::equal(
                    'shoeSize',
                    '12',
                ),
            ),
            0,
        ];
        yield 'a present filter on an unrecognized type an entry stores is undefined' => [
            Filters::present('shoeSize'),
            0,
        ];
    }

    #[DataProvider('filterProvider')]
    public function test_filter_evaluation_over_the_wire(
        FilterInterface $filter,
        int $expected,
    ): void {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search($filter)
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            $expected,
            $entries,
        );
    }

    public function testRequestingABaseTypeReturnsItsTaggedVariants(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'), 'mail')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        $alice = $entries->first();
        self::assertNotNull($alice);
        self::assertSame(
            ['alice@foo.bar'],
            $alice->get(new Attribute('mail'), true)?->getValues(),
        );
        self::assertSame(
            ['alice-en@foo.bar'],
            $alice->get(new Attribute('mail;lang-en'), true)?->getValues(),
        );
    }

    public function testRequestingEntryDnReturnsTheEntryDn(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'), 'entryDN')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            ['cn=alice,ou=people,dc=foo,dc=bar'],
            $entries->first()?->get(new Attribute('entryDN'), true)?->getValues(),
        );
    }

    public function testRequestingAllOperationalAttributesReturnsEntryDn(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'), '+')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            ['cn=alice,ou=people,dc=foo,dc=bar'],
            $entries->first()?->get(new Attribute('entryDN'), true)?->getValues(),
        );
    }

    public function testRequestingEntryDnByItsOidReturnsIt(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'), '1.3.6.1.1.20')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            ['cn=alice,ou=people,dc=foo,dc=bar'],
            $entries->first()?->get(new Attribute('entryDN'), true)?->getValues(),
        );
    }

    public function testEntryDnIsOperationalSoItIsNotReturnedByDefault(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertNull(
            $entries->first()?->get(new Attribute('entryDN'), true),
        );
    }

    public function testRequestingASupertypeReturnsItsSubtypeValues(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'), 'name')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        $alice = $entries->first();
        self::assertNotNull($alice);
        self::assertSame(
            ['alice'],
            $alice->get(new Attribute('cn'), true)?->getValues(),
        );
        self::assertSame(
            ['Smith'],
            $alice->get(new Attribute('sn'), true)?->getValues(),
        );
    }

    public function testRequestingATypeByItsOidReturnsIt(): void
    {
        $this->authenticateUser();

        // Filtering on a different attribute, so only the OID can be what asks for cn.
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('sn', 'Smith'), '2.5.4.3')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            ['alice'],
            $entries->first()?->get(new Attribute('cn'), true)?->getValues(),
        );
    }

    public function testATypesOnlyRequestKeepsAttributeOptions(): void
    {
        $this->authenticateUser();

        $request = Operations::search(Filters::equal('cn', 'alice'), 'mail')
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();
        $request->setAttributesOnly(true);

        $alice = $this->ldapClient()->search($request)->first();
        self::assertNotNull($alice);

        $descriptions = array_map(
            static fn(Attribute $attribute): string => $attribute->getDescription(),
            $alice->getAttributes(),
        );
        sort($descriptions);
        self::assertSame(
            ['mail', 'mail;lang-en'],
            $descriptions,
        );
    }

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
            6,
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

    public function testCompareAppliesTheSchemaDeclaredMatchingRule(): void
    {
        $this->authenticateUser();

        // employeeNumber matches case exactly, so a case folded comparison must not be true.
        self::assertTrue($this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'employeeNumber',
            'A1b2C3',
        ));
        self::assertFalse($this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'employeeNumber',
            'a1b2c3',
        ));
    }

    public function testCompareAgreesWithTheSameAssertionAsAFilter(): void
    {
        $this->authenticateUser();

        foreach (['A1b2C3', 'a1b2c3'] as $assertion) {
            $matched = $this->ldapClient()->search(
                Operations::search(Filters::equal('employeeNumber', $assertion))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
            );

            self::assertSame(
                count($matched) === 1,
                $this->ldapClient()->compare(
                    'cn=alice,ou=people,dc=foo,dc=bar',
                    'employeeNumber',
                    $assertion,
                ),
            );
        }
    }

    public function testCompareIsFalseWhenTheEntryLacksTheAttribute(): void
    {
        $this->authenticateUser();

        self::assertFalse($this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'telephoneNumber',
            '555',
        ));
    }

    public function testCompareIsFalseForAnUnrecognizedAttributeType(): void
    {
        $this->authenticateUser();

        // The assertion is Undefined rather than false, but neither is a match.
        self::assertFalse($this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'shoeSize',
            '12',
        ));
    }

    public function testCompareCoversValuesHeldBySubtypes(): void
    {
        $this->authenticateUser();

        // RFC 4512 2.5.2: cn is a subtype of name, so its value answers a comparison against the supertype.
        self::assertTrue($this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'name',
            'alice',
        ));
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
     * RFC 4511 4.5.1 constrains these fields, and the decoder only checks their type, so an out-of-range value
     * would otherwise be coerced into a request the client never made.
     *
     * @return iterable<string, array{SearchRequest}>
     */
    public static function outOfRangeSearchParameterProvider(): iterable
    {
        yield 'a scope above the enumeration' => [
            self::rangeProbeRequest()->setScope(3),
        ];
        yield 'a negative scope' => [
            self::rangeProbeRequest()->setScope(-1),
        ];
        yield 'an alias value above the enumeration' => [
            self::rangeProbeRequest()->setDereferenceAliases(4),
        ];
        yield 'a negative size limit' => [
            self::rangeProbeRequest()->setSizeLimit(-1),
        ];
        yield 'a negative time limit' => [
            self::rangeProbeRequest()->setTimeLimit(-1),
        ];
    }

    #[DataProvider('outOfRangeSearchParameterProvider')]
    public function test_a_search_parameter_outside_its_range_is_a_protocol_error(SearchRequest $request): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $this->ldapClient()->search($request);
    }

    /**
     * The clamp is applied with min(), so a negative limit would win it and lift the ceiling entirely.
     */
    public function testANegativeSizeLimitCannotDefeatTheServerMaximum(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--seed-entries=10',
                '--max-search-size=2',
            ],
        );
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->setSizeLimit(-1),
        );
    }

    private static function rangeProbeRequest(): SearchRequest
    {
        return Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar');
    }
}
