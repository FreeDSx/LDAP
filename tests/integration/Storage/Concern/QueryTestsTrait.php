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
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
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
     * The seed holds seven entries; only cn=alice carries uidNumber, mail and labeledURI. Each backend runs these,
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
            Filters::not(Filters::present('title')),
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

        // A SQL predicate narrower than the item it stands for cannot be complemented: the sidecar keys on the
        // bare type, so negating it would drop the entries the option excludes rather than return them.
        yield 'negating a tagged assertion the bare type would match' => [
            Filters::not(Filters::equal(
                'mail;lang-en',
                'alice@foo.bar',
            )),
            8,
        ];
        yield 'negating an absent tagged description' => [
            Filters::not(Filters::present('mail;lang-fr')),
            8,
        ];
        // No substring index covers employeeNumber, so the item stands for a bare presence check.
        yield 'negating a contains on an unindexed type' => [
            Filters::not(Filters::contains(
                'employeeNumber',
                'zzz',
            )),
            8,
        ];

        // RFC 4512 2.5.2: an assertion on the base type covers its tagged variants and its subtypes.
        yield 'the base type matches a value held under an option' => [
            Filters::equal('mail', 'alice-en@foo.bar'),
            1,
        ];

        // RFC 4512 2.5.2.1: a description is a subtype of the same type carrying any subset of its options.
        yield 'an option subset reaches a description carrying more' => [
            Filters::equal(
                'mail;lang-de',
                'alice-de-en@foo.bar',
            ),
            1,
        ];
        yield 'either option alone reaches it' => [
            Filters::equal(
                'mail;lang-en',
                'alice-de-en@foo.bar',
            ),
            1,
        ];
        yield 'the bare type reaches it too' => [
            Filters::equal(
                'mail',
                'alice-de-en@foo.bar',
            ),
            1,
        ];
        yield 'the full option set reaches it' => [
            Filters::equal(
                'mail;lang-de;lang-en',
                'alice-de-en@foo.bar',
            ),
            1,
        ];
        // The option order is irrelevant, since a description is its type plus a set.
        yield 'the option set is unordered' => [
            Filters::equal(
                'mail;lang-en;lang-de',
                'alice-de-en@foo.bar',
            ),
            1,
        ];
        // An option the stored description does not carry makes the assertion a subtype of nothing held.
        yield 'an option the description lacks matches nothing' => [
            Filters::equal(
                'mail;lang-de;lang-fr',
                'alice-de-en@foo.bar',
            ),
            0,
        ];
        // A supertype description must not answer an assertion on its own subtype.
        yield 'a tagged assertion does not reach the untagged value' => [
            Filters::equal(
                'mail;lang-de',
                'alice@foo.bar',
            ),
            0,
        ];
        yield 'a supertype matches a value held by its subtype' => [
            Filters::equal('name', 'alice'),
            1,
        ];
        // RFC 4519 gives ou SUP name, so an assertion on name reaches an ou value too.
        yield 'name reaches an organizational unit value' => [
            Filters::equal('name', 'people'),
            1,
        ];
        // member, seeAlso and roleOccupant are all SUP distinguishedName, the last inheriting its rule as well.
        yield 'distinguishedName reaches its DN-valued subtypes' => [
            Filters::equal(
                'distinguishedName',
                'cn=admin,dc=foo,dc=bar',
            ),
            5,
        ];

        // RFC 4511 4.5.1.7.7.
        yield 'extensible with an explicit matching rule' => [
            Filters::extensible('cn', 'ALICE', '2.5.13.2', false),
            1,
        ];
        yield 'extensible without a rule uses the type EQUALITY' => [
            Filters::extensible('labeledURI', 'A1b2C3', null, false),
            1,
        ];
        yield 'extensible without a rule respects a case exact EQUALITY' => [
            Filters::extensible('labeledURI', 'a1b2c3', null, false),
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

        // RFC 4518 2.2 maps these to nothing, so an assertion carrying one still matches the stored value.
        yield 'an assertion carrying a left to right mark still matches' => [
            Filters::equal('cn', "adm\u{200E}in"),
            1,
        ];
        yield 'an assertion carrying a soft hyphen still matches' => [
            Filters::equal('cn', "adm\u{00AD}in"),
            1,
        ];
        yield 'an assertion carrying a zero width space still matches' => [
            Filters::equal('cn', "adm\u{200B}in"),
            1,
        ];
        yield 'an assertion carrying an ascii control still matches' => [
            Filters::equal('cn', "adm\x01in"),
            1,
        ];

        // RFC 4518 2.3 folds per RFC 3454 B.2 rather than lowercasing, so sharp s and "ss" are one value.
        yield 'sharp s folds to a double s' => [
            Filters::equal('displayName', 'strasse'),
            1,
        ];
        yield 'the spelled out form matches the sharp s whatever its case' => [
            Filters::equal('displayName', 'STRASSE'),
            1,
        ];

        // No approximate rule is implemented, so it must answer as the type's equality rule does.
        yield 'approximate on a case exact type rejects a case difference' => [
            Filters::approximate('labeledURI', 'a1b2c3'),
            0,
        ];
        yield 'approximate on a case exact type accepts the exact value' => [
            Filters::approximate('labeledURI', 'A1b2C3'),
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

        // RFC 4512 4.2: derived from server configuration, so it matches without being stored.
        yield 'subschemaSubentry is present on every entry' => [
            Filters::present('subschemaSubentry'),
            8,
        ];
        yield 'subschemaSubentry matches the configured subschema dn' => [
            Filters::equal(
                'subschemaSubentry',
                'cn=Subschema',
            ),
            8,
        ];
        yield 'subschemaSubentry matches nothing for another dn' => [
            Filters::equal(
                'subschemaSubentry',
                'cn=SomewhereElse',
            ),
            0,
        ];
        yield 'subschemaSubentry matches by its oid' => [
            Filters::equal(
                '2.5.18.10',
                'cn=Subschema',
            ),
            8,
        ];

        // RFC 4517 4.2.26: objectClass matches on the identifier, so either spelling of it names the same classes.
        yield 'objectClass matches a stored descriptor by its oid' => [
            Filters::equal(
                'objectClass',
                '2.5.6.9',
            ),
            3,
        ];
        yield 'objectClass matches the same classes by descriptor' => [
            Filters::equal(
                'objectClass',
                'groupOfNames',
            ),
            3,
        ];
        yield 'objectClass matches a long form oid' => [
            Filters::equal(
                'objectClass',
                '2.16.840.1.113730.3.2.2',
            ),
            3,
        ];
        yield 'a negated objectClass oid leaves the rest' => [
            Filters::not(Filters::equal(
                'objectClass',
                '2.5.6.9',
            )),
            5,
        ];
        yield 'an objectClass oid narrows an indexed conjunction' => [
            Filters::and(
                Filters::equal(
                    'cn',
                    'alice',
                ),
                Filters::equal(
                    'objectClass',
                    '2.16.840.1.113730.3.2.2',
                ),
            ),
            1,
        ];

        // RFC 4517 4.2.26: a descriptor the schema does not define makes the item Undefined, not merely unmatched.
        yield 'an unknown objectClass descriptor matches nothing' => [
            Filters::equal(
                'objectClass',
                'bogusClass',
            ),
            0,
        ];
        yield 'a negated unknown objectClass descriptor stays undefined' => [
            Filters::not(Filters::equal(
                'objectClass',
                'bogusClass',
            )),
            0,
        ];

        // X.501: only the suffix and ou=people have children, and it is derived rather than stored on any of them.
        yield 'hasSubordinates matches only entries with children' => [
            Filters::equal(
                'hasSubordinates',
                'TRUE',
            ),
            2,
        ];
        yield 'hasSubordinates matches every leaf' => [
            Filters::equal(
                'hasSubordinates',
                'FALSE',
            ),
            6,
        ];
        yield 'hasSubordinates is present on every entry' => [
            Filters::present('hasSubordinates'),
            8,
        ];
        yield 'hasSubordinates matches by its oid' => [
            Filters::equal(
                '2.5.18.9',
                'TRUE',
            ),
            2,
        ];
        yield 'a negated hasSubordinates leaves the leaves' => [
            Filters::not(Filters::equal(
                'hasSubordinates',
                'TRUE',
            )),
            6,
        ];

        // The reference servers all resolve the indexed term first, so this must stay answerable alongside one.
        yield 'hasSubordinates narrows an indexed conjunction' => [
            Filters::and(
                Filters::equal(
                    'cn',
                    'alice',
                ),
                Filters::equal(
                    'hasSubordinates',
                    'FALSE',
                ),
            ),
            1,
        ];
        yield 'hasSubordinates excludes an indexed conjunction' => [
            Filters::and(
                Filters::equal(
                    'cn',
                    'alice',
                ),
                Filters::equal(
                    'hasSubordinates',
                    'TRUE',
                ),
            ),
            0,
        ];

        // RFC 5234 2.3 makes the quoted ABNF literals case-insensitive.
        yield 'a lowercase hasSubordinates assertion matches the same entries' => [
            Filters::equal(
                'hasSubordinates',
                'true',
            ),
            2,
        ];
        yield 'a non boolean hasSubordinates assertion is undefined' => [
            Filters::equal(
                'hasSubordinates',
                'BOGUS',
            ),
            0,
        ];
        yield 'a negated invalid hasSubordinates assertion stays undefined' => [
            Filters::not(Filters::equal(
                'hasSubordinates',
                'BOGUS',
            )),
            0,
        ];

        // The seed spells each of these two ways, so a store keying values by anything but the attribute's own
        // rule answers with only the spelling it was handed.
        yield 'distinguishedNameMatch ignores RDN spacing and case' => [
            Filters::equal(
                'seeAlso',
                'cn=admin,dc=foo,dc=bar',
            ),
            2,
        ];
        yield 'distinguishedNameMatch matches a decorated assertion too' => [
            Filters::equal(
                'seeAlso',
                'CN=Admin,  DC=Foo,  DC=Bar',
            ),
            2,
        ];
        yield 'uniqueMemberMatch ignores RDN spacing and case' => [
            Filters::equal(
                'uniqueMember',
                'cn=admin,dc=foo,dc=bar',
            ),
            2,
        ];
        // roleOccupant declares no EQUALITY, so this only holds if the supertype's rule is inherited.
        yield 'an inherited distinguishedNameMatch ignores RDN spacing and case' => [
            Filters::equal(
                'roleOccupant',
                'CN=Admin,  DC=Foo,  DC=Bar',
            ),
            2,
        ];
        yield 'telephoneNumberMatch ignores hyphens and spaces' => [
            Filters::equal(
                'telephoneNumber',
                '+14085551212',
            ),
            2,
        ];
        yield 'telephoneNumberMatch approximates on the same profile' => [
            Filters::approximate(
                'telephoneNumber',
                '+14085551212',
            ),
            2,
        ];
        yield 'numericStringMatch ignores spaces' => [
            Filters::equal(
                'x121Address',
                '11112222',
            ),
            2,
        ];
        yield 'numericStringMatch matches a spaced assertion too' => [
            Filters::equal(
                'x121Address',
                '1111 2222',
            ),
            2,
        ];
        // RFC 4519 2.35 wires telephoneNumber to telephoneNumberSubstringsMatch, which drops the punctuation.
        yield 'a telephone substring ignores the punctuation around it' => [
            Filters::substring(
                'telephoneNumber',
                null,
                '4085551212',
            ),
            2,
        ];
        yield 'a telephone prefix ignores the punctuation around it' => [
            Filters::substring(
                'telephoneNumber',
                '+1408',
                null,
            ),
            2,
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

    /**
     * @return iterable<string, array{string, FilterInterface, int}>
     */
    public static function singleLevelFilterProvider(): iterable
    {
        // cn=alice carries sn=Smith but sits under ou=people, so no direct child of the root matches.
        yield 'a value held only by a grandchild matches nothing' => [
            'dc=foo,dc=bar',
            Filters::equal('sn', 'Smith'),
            0,
        ];
        yield 'direct children matching are returned' => [
            'dc=foo,dc=bar',
            Filters::equal('sn', 'Admin'),
            2,
        ];
        yield 'the grandchild matches under its own parent' => [
            'ou=people,dc=foo,dc=bar',
            Filters::equal('sn', 'Smith'),
            1,
        ];
        yield 'a presence filter narrows to children carrying it' => [
            'dc=foo,dc=bar',
            Filters::present('sn'),
            2,
        ];
    }

    #[DataProvider('singleLevelFilterProvider')]
    public function test_single_level_filter_evaluation(
        string $base,
        FilterInterface $filter,
        int $expected,
    ): void {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search($filter)
                ->base($base)
                ->useSingleLevelScope(),
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

    public function testRequestingSubschemaSubentryReturnsTheSubschemaDn(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'), 'subschemaSubentry')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            ['cn=Subschema'],
            $entries->first()?->get(new Attribute('subschemaSubentry'), true)?->getValues(),
        );
    }

    public function testSubschemaSubentryIsReturnedOnABaseScopedRead(): void
    {
        $this->authenticateUser();

        // The discovery flow every schema-aware client uses: read it from the entry it governs.
        $entries = $this->ldapClient()->search(
            Operations::read('cn=alice,ou=people,dc=foo,dc=bar', 'subschemaSubentry'),
        );

        self::assertSame(
            ['cn=Subschema'],
            $entries->first()?->get(new Attribute('subschemaSubentry'), true)?->getValues(),
        );
    }

    public function testRequestingAllOperationalAttributesReturnsSubschemaSubentry(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'), '+')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            ['cn=Subschema'],
            $entries->first()?->get(new Attribute('subschemaSubentry'), true)?->getValues(),
        );
    }

    public function testSubschemaSubentryIsOperationalSoItIsNotReturnedByDefault(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertNull(
            $entries->first()?->get(new Attribute('subschemaSubentry'), true),
        );
    }

    public function testEntryDnIsReturnedOnABaseScopedRead(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::read('cn=alice,ou=people,dc=foo,dc=bar', 'entryDN'),
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

    /**
     * @param non-empty-string $baseDn
     */
    #[DataProvider('refusedBaseDnProvider')]
    public function testAMalformedBaseDnIsRefusedWithoutEndingTheSession(string $baseDn): void
    {
        $this->authenticateUser();
        $code = null;

        try {
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base($baseDn)
                    ->useBaseScope(),
            );
        } catch (OperationException $e) {
            $code = $e->getCode();
        }

        self::assertSame(
            ResultCode::INVALID_DN_SYNTAX,
            $code,
        );

        // A malformed DN names one message; the connection must stay usable for the next one.
        self::assertCount(
            1,
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base('dc=foo,dc=bar')
                    ->useBaseScope(),
            ),
        );
    }

    /**
     * @return iterable<string, array{non-empty-string}>
     */
    public static function refusedBaseDnProvider(): iterable
    {
        yield 'attribute type outside the grammar' => [
            '!!!=bar,dc=foo,dc=bar',
        ];
        yield 'attribute type with an inner space' => [
            'cn foo=bar,dc=foo,dc=bar',
        ];
        yield 'empty attribute type' => [
            '=bar,dc=foo,dc=bar',
        ];
        yield 'attribute option in an rdn' => [
            'cn;lang-en=alice,dc=foo,dc=bar',
        ];
        yield 'oid arc with a leading zero' => [
            '2.05.4.3=alice,dc=foo,dc=bar',
        ];
        yield 'hexstring value form' => [
            'cn=#0C03616263,dc=foo,dc=bar',
        ];
        yield 'raw null byte in a value' => [
            "cn=a\0b,dc=foo,dc=bar",
        ];
    }

    #[DataProvider('baseScopeFilterProvider')]
    public function testABaseScopeSearchAppliesTheFilter(
        FilterInterface $filter,
        int $expected,
    ): void {
        $this->authenticateUser();

        self::assertCount(
            $expected,
            $this->ldapClient()->search(
                Operations::search($filter)
                    ->base('ou=people,dc=foo,dc=bar')
                    ->useBaseScope(),
            ),
        );
    }

    /**
     * RFC 4511 4.5.1 applies the filter at every scope; ou=people is an organizationalUnit holding only ou.
     *
     * @return iterable<string, array{FilterInterface, int}>
     */
    public static function baseScopeFilterProvider(): iterable
    {
        yield 'a filter the base entry matches' => [
            Filters::equal('objectClass', 'organizationalUnit'),
            1,
        ];
        yield 'a presence filter the base entry matches' => [
            Filters::present('objectClass'),
            1,
        ];
        yield 'an object class the base entry does not hold' => [
            Filters::equal('objectClass', 'inetOrgPerson'),
            0,
        ];
        yield 'a value the base entry does not hold' => [
            Filters::equal('ou', 'nosuchvalue'),
            0,
        ];
        yield 'an attribute the base entry does not hold' => [
            Filters::present('uidNumber'),
            0,
        ];
        yield 'a negation no entry can satisfy' => [
            Filters::not(Filters::present('objectClass')),
            0,
        ];
    }

    public function testAHexEscapeNamesTheSameEntryAsTheCharacterItEncodes(): void
    {
        $this->authenticateUser();

        // RFC 4514 4: \61 is the hex escape for "a", so this base denotes cn=alice.
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('cn=\61lice,ou=people,dc=foo,dc=bar')
                ->useBaseScope(),
        );

        self::assertSame(
            ['alice'],
            $entries->first()?->get(new Attribute('cn'), true)?->getValues(),
        );
    }

    public function testBothSpellingsOfAnEscapedCommaNameOneEntry(): void
    {
        $this->authenticateUser();

        // The seed holds cn=Smith\, John; \2c is the hex spelling of the same escaped comma.
        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('cn=Smith\2c John,dc=foo,dc=bar')
                ->useBaseScope(),
        );

        self::assertSame(
            ['Smith, John'],
            $entries->first()?->get(new Attribute('cn'), true)?->getValues(),
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
            ['mail', 'mail;lang-de;lang-en', 'mail;lang-en'],
            $descriptions,
        );
    }

    /**
     * RFC 4512 2.5.2.1: naming a subset of the options selects the descriptions carrying at least those.
     */
    public function testRequestingAnOptionSubsetReturnsTheDescriptionsCarryingMore(): void
    {
        $this->authenticateUser();

        $alice = $this->searchSelecting(
            'alice',
            'mail;lang-de',
        );
        self::assertNotNull($alice);

        self::assertSame(
            ['mail;lang-de;lang-en'],
            $this->descriptionsOf($alice),
        );
    }

    public function testRequestingAnOptionTheDescriptionLacksReturnsNothing(): void
    {
        $this->authenticateUser();

        $alice = $this->searchSelecting(
            'alice',
            'mail;lang-fr',
        );
        self::assertNotNull($alice);

        self::assertSame(
            [],
            $this->descriptionsOf($alice),
        );
    }

    /**
     * A supertype description must not be returned for a request naming one of its subtypes.
     */
    public function testRequestingATaggedDescriptionDoesNotReturnTheUntaggedOne(): void
    {
        $this->authenticateUser();

        $alice = $this->searchSelecting(
            'alice',
            'mail;lang-en',
        );
        self::assertNotNull($alice);

        self::assertSame(
            ['mail;lang-de;lang-en', 'mail;lang-en'],
            $this->descriptionsOf($alice),
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

    /**
     * RFC 4511 4.10: compareFalse means the values did not match, so an Undefined assertion needs its own code.
     */
    public function testCompareRefusesAnUnrecognizedAttributeType(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNDEFINED_ATTRIBUTE_TYPE);

        $this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'shoeSize',
            '9',
        );
    }

    public function testCompareRefusesAnAssertionValueTheSyntaxRejects(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'uidNumber',
            'abc',
        );
    }

    /**
     * A defined type the entry lacks is False rather than Undefined, so it keeps answering compareFalse.
     */
    public function testCompareAnswersFalseWhenTheEntryLacksTheAttribute(): void
    {
        $this->authenticateUser();

        self::assertFalse($this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'title',
            'anything',
        ));
    }

    public function testCompareAppliesTheSchemaDeclaredMatchingRule(): void
    {
        $this->authenticateUser();

        // labeledURI matches case exactly, so a case folded comparison must not be true.
        self::assertTrue($this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'labeledURI',
            'A1b2C3',
        ));
        self::assertFalse($this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'labeledURI',
            'a1b2c3',
        ));
    }

    public function testCompareAgreesWithTheSameAssertionAsAFilter(): void
    {
        $this->authenticateUser();

        foreach (['A1b2C3', 'a1b2c3'] as $assertion) {
            $matched = $this->ldapClient()->search(
                Operations::search(Filters::equal('labeledURI', $assertion))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
            );

            self::assertSame(
                count($matched) === 1,
                $this->ldapClient()->compare(
                    'cn=alice,ou=people,dc=foo,dc=bar',
                    'labeledURI',
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

    /**
     * A supertype the index cannot answer, so every candidate reaches the evaluator the limit counts.
     */
    public function testAFilterEvaluatedInPhpTripsTheLookthroughLimit(): void
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
            Operations::search(Filters::equal('name', 'no-entry-has-this'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
    }

    /**
     * A base naming an alias resolves to the entry it names (RFC 4511 4.5.1.3 derefFindingBaseObj), while an alias
     * met while searching is returned as the ordinary entry it is rather than failing the search.
     */
    public function testAliasDereferencing(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', static::storageExtraArgs());
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray('cn=ref,dc=foo,dc=bar', [
            'objectClass' => ['top', 'alias', 'extensibleObject'],
            'cn' => 'ref',
            'aliasedObjectName' => 'cn=user,dc=foo,dc=bar',
        ]));

        try {
            self::assertCount(
                1,
                $this->ldapClient()->search(
                    Operations::search(Filters::equal('cn', 'ref'))
                        ->base('dc=foo,dc=bar')
                        ->useSubtreeScope(),
                ),
                'An alias in scope is an ordinary entry when nothing is dereferenced.',
            );

            self::assertCount(
                1,
                $this->ldapClient()->search(
                    Operations::search(Filters::equal('cn', 'ref'))
                        ->base('dc=foo,dc=bar')
                        ->useSubtreeScope()
                        ->setDereferenceAliases(SearchRequest::DEREF_ALWAYS),
                ),
                'An alias in scope stays an ordinary entry rather than failing the search.',
            );

            $viaAlias = $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base('cn=ref,dc=foo,dc=bar')
                    ->useBaseScope()
                    ->setDereferenceAliases(SearchRequest::DEREF_FINDING_BASE_OBJECT),
            );

            self::assertSame(
                'cn=user,dc=foo,dc=bar',
                strtolower((string) $viaAlias->first()?->getDn()),
                'A base naming an alias resolves to the entry it names.',
            );

            self::assertSame(
                'cn=ref,dc=foo,dc=bar',
                strtolower((string) $this->ldapClient()->search(
                    Operations::search(Filters::present('objectClass'))
                        ->base('cn=ref,dc=foo,dc=bar')
                        ->useBaseScope(),
                )->first()?->getDn()),
                'The same base names the alias itself when nothing is dereferenced.',
            );
        } finally {
            $this->ldapClient()->delete('cn=ref,dc=foo,dc=bar');
        }
    }

    public function testABaseAliasNamingAMissingEntryIsAnAliasProblem(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', static::storageExtraArgs());
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray('cn=dangle,dc=foo,dc=bar', [
            'objectClass' => ['top', 'alias', 'extensibleObject'],
            'cn' => 'dangle',
            'aliasedObjectName' => 'cn=nothere,dc=foo,dc=bar',
        ]));

        try {
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base('cn=dangle,dc=foo,dc=bar')
                    ->useBaseScope()
                    ->setDereferenceAliases(SearchRequest::DEREF_FINDING_BASE_OBJECT),
            );
            self::fail('Expected the dangling alias to be refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ALIAS_PROBLEM,
                $e->getCode(),
            );
        } finally {
            $this->ldapClient()->delete('cn=dangle,dc=foo,dc=bar');
        }
    }

    public function testABaseAliasThatLoopsIsAnAliasProblem(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', static::storageExtraArgs());
        $this->authenticateAdmin();

        foreach ([['loopa', 'loopb'], ['loopb', 'loopa']] as [$name, $target]) {
            $this->ldapClient()->create(Entry::fromArray("cn=$name,dc=foo,dc=bar", [
                'objectClass' => ['top', 'alias', 'extensibleObject'],
                'cn' => $name,
                'aliasedObjectName' => "cn=$target,dc=foo,dc=bar",
            ]));
        }

        try {
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base('cn=loopa,dc=foo,dc=bar')
                    ->useBaseScope()
                    ->setDereferenceAliases(SearchRequest::DEREF_FINDING_BASE_OBJECT),
            );
            self::fail('Expected the alias loop to be refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ALIAS_PROBLEM,
                $e->getCode(),
            );
        } finally {
            $this->ldapClient()->delete('cn=loopa,dc=foo,dc=bar');
            $this->ldapClient()->delete('cn=loopb,dc=foo,dc=bar');
        }
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

    /**
     * A filter the backend answers exactly is still bounded by the handler, which needs one match past the limit.
     */
    public function testAnExactlyAnswerableFilterSignalsSizeLimitOverflow(): void
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

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::SIZE_LIMIT_EXCEEDED);

        $this->ldapClient()->search(
            Operations::search(Filters::equal('sn', 'Seeded'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->setSizeLimit(3),
        );
    }

    public function testAnExactlyAnswerableFilterWithinTheSizeLimitReturnsEveryMatch(): void
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

        self::assertCount(
            10,
            $this->ldapClient()->search(
                Operations::search(Filters::equal('sn', 'Seeded'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope()
                    ->setSizeLimit(10),
            ),
        );
    }

    public function testMatchedDnIsEmptyOnASuccessfulSearch(): void
    {
        $this->authenticateUser();

        $response = $this->ldapClient()->send(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        $done = $response?->getResponse();
        self::assertInstanceOf(
            SearchResultDone::class,
            $done,
        );
        self::assertSame(
            '',
            $done->getDn()->toString(),
        );
    }

    public function testMatchedDnNamesTheClosestAncestorWhenTheBaseIsMissing(): void
    {
        $this->authenticateUser();

        try {
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base('cn=nope,ou=people,dc=foo,dc=bar')
                    ->useSubtreeScope(),
            );
            self::fail('The missing base should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::NO_SUCH_OBJECT,
                $e->getCode(),
            );
            self::assertSame(
                'ou=people,dc=foo,dc=bar',
                $e->getMatchedDn()?->toString(),
            );
        }
    }

    private static function rangeProbeRequest(): SearchRequest
    {
        return Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar');
    }

    private function searchSelecting(
        string $cn,
        string $selector,
    ): ?Entry {
        return $this->ldapClient()->search(
            Operations::search(
                Filters::equal('cn', $cn),
                $selector,
            )
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        )->first();
    }

    /**
     * @return list<string>
     */
    private function descriptionsOf(Entry $entry): array
    {
        $descriptions = array_map(
            static fn(Attribute $attribute): string => $attribute->getDescription(),
            $entry->getAttributes(),
        );
        sort($descriptions);

        return $descriptions;
    }
}
