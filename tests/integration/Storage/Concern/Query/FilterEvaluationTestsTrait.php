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
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Real filter-based searches over the wire, verifying filter evaluation end to end.
 */
trait FilterEvaluationTestsTrait
{
    /**
     * Each filter choice RFC 4511 4.5.1 defines, and the absolute filters RFC 4526 adds.
     *
     * @return iterable<string, array{FilterInterface, int}>
     */
    public static function filterChoiceProvider(): iterable
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
    }

    /**
     * Negation, which must leave an Undefined item Undefined rather than turn it True.
     *
     * @return iterable<string, array{FilterInterface, int}>
     */
    public static function negationFilterProvider(): iterable
    {
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
    }

    /**
     * Which held descriptions an assertion reaches through options, subtypes, and supertypes.
     *
     * @return iterable<string, array{FilterInterface, int}>
     */
    public static function attributeDescriptionFilterProvider(): iterable
    {
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
    }

    /**
     * Extensible matches: by a named rule, by the type's own EQUALITY, and against the DN.
     *
     * @return iterable<string, array{FilterInterface, int}>
     */
    public static function extensibleMatchFilterProvider(): iterable
    {
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
        // RFC 4517 4.2.20: an ordering rule is TRUE when the value is less than the assertion, so 99 and 100 match.
        yield 'extensible with an integer ordering rule matches values below the assertion' => [
            Filters::extensible(
                'uidNumber',
                '101',
                '2.5.13.15',
                false,
            ),
            2,
        ];
        yield 'extensible with an integer ordering rule excludes the assertion itself' => [
            Filters::extensible(
                'uidNumber',
                '99',
                'integerOrderingMatch',
                false,
            ),
            0,
        ];
        // RFC 4517 4.2.12: admin and admins sort before alice once case is folded.
        yield 'extensible with a case ignore ordering rule matches values below the assertion' => [
            Filters::extensible(
                'cn',
                'ALICE',
                'caseIgnoreOrderingMatch',
                false,
            ),
            2,
        ];
        yield 'extensible with a substring rule is Undefined' => [
            Filters::extensible(
                'cn',
                'alice',
                'caseIgnoreSubstringsMatch',
                false,
            ),
            0,
        ];
        yield 'negating an extensible with a substring rule is still Undefined' => [
            Filters::not(Filters::extensible(
                'cn',
                'al*',
                '2.5.13.4',
                false,
            )),
            0,
        ];
        // RFC 4511 4.5.1.7.7: the rule determines the assertion syntax, and a value it rejects is Undefined.
        yield 'extensible with an assertion value the rule rejects is Undefined' => [
            Filters::extensible(
                'uidNumber',
                'abc',
                'integerOrderingMatch',
                false,
            ),
            0,
        ];
        yield 'negating an extensible with an assertion value the rule rejects is still Undefined' => [
            Filters::not(Filters::extensible(
                'uidNumber',
                'abc',
                'integerOrderingMatch',
                false,
            )),
            0,
        ];
        yield 'extensible with a signed integer assertion is Undefined as on the equality path' => [
            Filters::extensible(
                'uidNumber',
                '+100',
                'integerMatch',
                false,
            ),
            0,
        ];
        yield 'extensible bitAnd with a mask that is not an integer is Undefined' => [
            Filters::extensible(
                'uidNumber',
                'abc',
                '1.2.840.113556.1.4.803',
                false,
            ),
            0,
        ];
        // RFC 4517 4.2 assigns generalizedTimeMatch 2.5.13.27 and generalizedTimeOrderingMatch 2.5.13.28.
        yield 'negating generalizedTimeMatch named by its OID matches every stamped entry' => [
            Filters::not(Filters::extensible(
                'createTimestamp',
                '19700101000000Z',
                '2.5.13.27',
                false,
            )),
            8,
        ];
        yield 'generalizedTimeOrderingMatch named by its OID matches every earlier stamp' => [
            Filters::extensible(
                'createTimestamp',
                '99991231235959Z',
                '2.5.13.28',
                false,
            ),
            8,
        ];
        yield 'extensible bitAnd matches no value that is not an integer' => [
            Filters::extensible(
                'cn',
                '0',
                '1.2.840.113556.1.4.803',
                false,
            ),
            0,
        ];
    }

    /**
     * RFC 4518 string preparation, applied to the assertion and the stored value alike.
     *
     * @return iterable<string, array{FilterInterface, int}>
     */
    public static function stringPreparationFilterProvider(): iterable
    {
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
    }

    /**
     * Each type's own matching rule, whatever spelling the seed and the assertion use.
     *
     * @return iterable<string, array{FilterInterface, int}>
     */
    public static function matchingRuleFilterProvider(): iterable
    {
        // No approximate rule is implemented, so it must answer as the type's equality rule does.
        yield 'approximate on a case exact type rejects a case difference' => [
            Filters::approximate('labeledURI', 'a1b2c3'),
            0,
        ];
        yield 'approximate on a case exact type accepts the exact value' => [
            Filters::approximate('labeledURI', 'A1b2C3'),
            1,
        ];
        yield 'approximate on a linked attribute matches as equality does' => [
            Filters::approximate(
                'member',
                'CN=User, DC=Foo, DC=Bar',
            ),
            2,
        ];
        yield 'approximate on a computed attribute matches as equality does' => [
            Filters::approximate(
                'hasSubordinates',
                'TRUE',
            ),
            2,
        ];
        yield 'a negated approximate on a linked attribute excludes its holders' => [
            Filters::not(Filters::approximate(
                'member',
                'cn=user,dc=foo,dc=bar',
            )),
            6,
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

    /**
     * An assertion value the type's syntax rejects is Undefined, so it matches nothing even when negated.
     *
     * @return iterable<string, array{FilterInterface, int}>
     */
    public static function invalidAssertionValueFilterProvider(): iterable
    {
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
    }

    /**
     * A substring item applies the type's SUBSTR rule, and is Undefined on a type that declares none.
     *
     * @return iterable<string, array{FilterInterface, int}>
     */
    public static function substringRuleFilterProvider(): iterable
    {
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
    }

    /**
     * Attributes derived on read, which must match without having been requested or stored.
     *
     * @return iterable<string, array{FilterInterface, int}>
     */
    public static function derivedAttributeFilterProvider(): iterable
    {
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
    }

    /**
     * RFC 4517 4.2.26: objectClass matches on the class identifier, by descriptor or OID.
     *
     * @return iterable<string, array{FilterInterface, int}>
     */
    public static function objectClassFilterProvider(): iterable
    {
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
        yield 'objectClass matches a descriptor spelled in another case' => [
            Filters::equal(
                'objectClass',
                'GROUPOFNAMES',
            ),
            3,
        ];
        yield 'a negated objectClass descriptor leaves the rest' => [
            Filters::not(Filters::equal(
                'objectClass',
                'groupOfNames',
            )),
            5,
        ];
        yield 'an objectClass alternative beside its own negation matches every entry' => [
            Filters::or(
                Filters::equal(
                    'objectClass',
                    'groupOfNames',
                ),
                Filters::not(Filters::equal(
                    'objectClass',
                    '2.5.6.9',
                )),
            ),
            8,
        ];
        yield 'an objectClass item asserting an option no value carries matches nothing' => [
            Filters::equal(
                'objectClass;x-option',
                'groupOfNames',
            ),
            0,
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
        yield 'a negated approximate unknown objectClass descriptor stays undefined' => [
            Filters::not(Filters::approximate(
                'objectClass',
                'bogusClass',
            )),
            0,
        ];
    }

    #[DataProvider('filterChoiceProvider')]
    #[DataProvider('negationFilterProvider')]
    #[DataProvider('attributeDescriptionFilterProvider')]
    #[DataProvider('extensibleMatchFilterProvider')]
    #[DataProvider('stringPreparationFilterProvider')]
    #[DataProvider('matchingRuleFilterProvider')]
    #[DataProvider('invalidAssertionValueFilterProvider')]
    #[DataProvider('substringRuleFilterProvider')]
    #[DataProvider('derivedAttributeFilterProvider')]
    #[DataProvider('objectClassFilterProvider')]
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

    #[DataProvider('supertypeFilterProvider')]
    public function testASupertypeFilterMatchesTheSameEntriesWhateverAttributesAreRequested(FilterInterface $filter): void
    {
        $this->authenticateUser();

        $withEveryAttribute = $this->dnsMatching(
            $filter,
            '*',
        );

        self::assertNotSame(
            [],
            $withEveryAttribute,
        );
        self::assertSame(
            $withEveryAttribute,
            $this->dnsMatching(
                $filter,
                SearchRequest::ATTRIBUTES_NONE,
            ),
        );
    }

    /**
     * @return iterable<string, array{FilterInterface}>
     */
    public static function supertypeFilterProvider(): iterable
    {
        yield 'an equality on a supertype' => [
            Filters::equal(
                'name',
                'alice',
            ),
        ];
        yield 'a substring on a supertype' => [
            Filters::startsWith(
                'name',
                'ali',
            ),
        ];
        yield 'a negated equality on a supertype' => [
            Filters::not(Filters::equal(
                'name',
                'alice',
            )),
        ];
        yield 'an equality reaching a DN-valued subtype' => [
            Filters::equal(
                'distinguishedName',
                'cn=admin,dc=foo,dc=bar',
            ),
        ];
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

    /**
     * @return list<string>
     */
    private function dnsMatching(
        FilterInterface $filter,
        string $selector,
    ): array {
        $dns = array_map(
            static fn(Entry $entry): string => $entry->getDn()->toString(),
            $this->ldapClient()->search(
                Operations::search(
                    $filter,
                    $selector,
                )
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
            )->toArray(),
        );
        sort($dns);

        return $dns;
    }
}
