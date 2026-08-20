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
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Add, delete, modify, and rename against the backend.
 */
trait WriteTestsTrait
{
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

    public function testAddRejectsAnAttributeCarryingNoValues(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $this->ldapClient()->create(new Entry(
            'cn=novalues,dc=foo,dc=bar',
            new Attribute('objectClass', 'inetOrgPerson'),
            new Attribute('cn', 'novalues'),
            new Attribute('sn', 'Novalues'),
            new Attribute('description'),
        ));
    }

    public function testModifyRejectsAnAddCarryingNoValues(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $this->ldapClient()->send(Operations::modify(
            'cn=alice,ou=people,dc=foo,dc=bar',
            Change::add(new Attribute('description')),
        ));
    }

    public function testRenameToANewRdnThatIsNotUtf8IsRefused(): void
    {
        $this->authenticateAdmin();

        try {
            $this->ldapClient()->rename(
                'cn=alice,ou=people,dc=foo,dc=bar',
                "cn=\xFF\xFE",
            );
            self::fail('The new RDN that is not UTF-8 should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INVALID_DN_SYNTAX,
                $e->getCode(),
            );
        }

        self::assertCount(
            1,
            $this->ldapClient()->search(
                Operations::search(Filters::equal('cn', 'alice'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
            ),
        );
    }

    public function testAddWithAHexstringDnIsRefused(): void
    {
        $this->authenticateAdmin();

        try {
            $this->ldapClient()->create(Entry::fromArray(
                'cn=#0C03616263,dc=foo,dc=bar',
                [
                    'cn' => 'abc',
                    'sn' => 'Hex',
                    'objectClass' => 'inetOrgPerson',
                ],
            ));
            self::fail('The hexstring DN form should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INVALID_DN_SYNTAX,
                $e->getCode(),
            );
        }
    }

    public function testAddWithAnEscapedLeadingSharpIsStoredAsALiteralValue(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=\23hashtag,dc=foo,dc=bar',
            [
                'cn' => '#hashtag',
                'sn' => 'Hash',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        try {
            $entries = $this->ldapClient()->search(
                Operations::search(Filters::equal('cn', '#hashtag'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
            );

            self::assertCount(1, $entries);
        } finally {
            $this->ldapClient()->delete('cn=\23hashtag,dc=foo,dc=bar');
        }
    }

    public function testAddRejectsDuplicateAttributeDescriptions(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ATTRIBUTE_OR_VALUE_EXISTS);

        $this->ldapClient()->create(new Entry(
            'cn=dupdesc,dc=foo,dc=bar',
            new Attribute('objectClass', 'inetOrgPerson'),
            new Attribute('cn', 'dupdesc'),
            new Attribute('CN', 'other'),
            new Attribute('sn', 'Dup'),
        ));
    }

    public function testAddRejectsEquivalentDuplicateValues(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ATTRIBUTE_OR_VALUE_EXISTS);

        $this->ldapClient()->create(new Entry(
            'cn=dupval,dc=foo,dc=bar',
            new Attribute('objectClass', 'inetOrgPerson'),
            new Attribute('cn', 'dupval'),
            new Attribute('sn', 'SAME', 'same'),
        ));
    }

    public function testAddRejectsExtensibleObjectWithoutAStructuralClass(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->ldapClient()->create(new Entry(
            'cn=extonly,dc=foo,dc=bar',
            new Attribute('objectClass', 'extensibleObject'),
            new Attribute('cn', 'extonly'),
        ));
    }

    public function testAddRejectsAnUndefinedAttributeEvenOnAnExtensibleObject(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNDEFINED_ATTRIBUTE_TYPE);

        $this->ldapClient()->create(new Entry(
            'cn=extundefined,dc=foo,dc=bar',
            new Attribute('objectClass', 'inetOrgPerson', 'extensibleObject'),
            new Attribute('cn', 'extundefined'),
            new Attribute('sn', 'Ext'),
            new Attribute('shoeSize', '12'),
        ));
    }

    public function testModifyRejectsChangingTheStructuralObjectClass(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_MODS_PROHIBITED);

        $this->ldapClient()->send(Operations::modify(
            'cn=nosn,dc=foo,dc=bar',
            Change::replace(new Attribute('objectClass', 'top', 'groupOfUniqueNames')),
            Change::add(new Attribute('uniqueMember', 'cn=user,dc=foo,dc=bar')),
            Change::delete(new Attribute('member')),
        ));
    }

    public function testAddAcceptsDeviceCarryingAnAuxiliaryPolicyClass(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(new Entry(
            'cn=policy-carrier,dc=foo,dc=bar',
            new Attribute('objectClass', 'top', 'device', 'pwdPolicy'),
            new Attribute('cn', 'policy-carrier'),
            new Attribute('pwdAttribute', 'userPassword'),
        ));

        self::assertCount(
            1,
            $this->ldapClient()->search(
                Operations::search(Filters::equal('cn', 'policy-carrier'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
            ),
        );

        $this->ldapClient()->delete('cn=policy-carrier,dc=foo,dc=bar');
    }

    /**
     * RDN values are folded case-insensitively whatever the attribute's EQUALITY rule says, so labeledURI names
     * one entry despite matching case-exactly everywhere else.
     *
     * A deliberate deviation: honouring caseExact here would make DNs differing only in case distinct entries, and
     * an accidental case difference is likelier than an intended one. Real world implementations genuinely already
     * behave differently on this point.
     */
    public function testRdnCaseIsFoldedEvenForACaseExactAttribute(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'labeledURI=CaseTest,dc=foo,dc=bar',
            [
                'cn' => 'casetest',
                'sn' => 'Case',
                'labeledURI' => 'CaseTest',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        try {
            $this->ldapClient()->create(Entry::fromArray(
                'labeledURI=casetest,dc=foo,dc=bar',
                [
                    'cn' => 'casetest2',
                    'sn' => 'Case',
                    'labeledURI' => 'casetest',
                    'objectClass' => 'inetOrgPerson',
                ],
            ));
            self::fail('The case-folded DN should have named the entry already added.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ENTRY_ALREADY_EXISTS,
                $e->getCode(),
            );
        } finally {
            $this->ldapClient()->delete('labeledURI=CaseTest,dc=foo,dc=bar');
        }
    }

    /**
     * @param non-empty-string $cn
     */
    #[DataProvider('invisiblyDifferentValueProvider')]
    public function testAddIsRefusedForADnDifferingOnlyByACodePointThatRendersAsNothing(string $cn): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->ldapClient()->create(Entry::fromArray("cn=$cn,dc=foo,dc=bar", [
            'cn' => $cn,
            'sn' => 'Impostor',
            'objectClass' => 'inetOrgPerson',
        ]));
    }

    /**
     * RFC 4518 2.2 maps these to nothing, so each names the seeded cn=admin and cannot be added beside it.
     *
     * @return iterable<string, array{non-empty-string}>
     */
    public static function invisiblyDifferentValueProvider(): iterable
    {
        yield 'left to right mark' => [
            "adm\u{200E}in",
        ];
        yield 'right to left mark' => [
            "adm\u{200F}in",
        ];
        yield 'soft hyphen' => [
            "adm\u{00AD}in",
        ];
        yield 'zero width space' => [
            "adm\u{200B}in",
        ];
        yield 'object replacement character' => [
            "adm\u{FFFC}in",
        ];
        yield 'ascii control' => [
            "adm\x01in",
        ];
    }

    public function testARenameOntoAnInvisiblyDifferentDnIsRefused(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        // Renaming keeps the parent, so this lands beside the seeded cn=admin under dc=foo,dc=bar.
        $this->ldapClient()->rename(
            'cn=nosn,dc=foo,dc=bar',
            "cn=adm\u{200E}in",
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

    public function testRejectedModifyLeavesTheEntryUnchanged(): void
    {
        $this->authenticateAdmin();

        // cn=user has no extensibleObject class, so removing a required attribute is actually refused.
        $entry = Entry::fromArray('cn=user,dc=foo,dc=bar');
        $entry->reset('sn');

        try {
            $this->ldapClient()->update($entry);
            self::fail('The schema violating modify should have been rejected.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::OBJECT_CLASS_VIOLATION,
                $e->getCode(),
            );
        }

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'sn')
                ->base('cn=user,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ['Admin'],
            $found->first()?->get('sn')?->getValues(),
        );
    }

    public function testAddAcceptsEveryAttributeGroupOfNamesPermits(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=allmay,dc=foo,dc=bar',
            [
                'objectClass' => 'groupOfNames',
                'cn' => 'allmay',
                'member' => 'cn=user,dc=foo,dc=bar',
                'businessCategory' => 'operations',
                'seeAlso' => 'cn=admin,dc=foo,dc=bar',
                'owner' => 'cn=admin,dc=foo,dc=bar',
                'ou' => 'people',
                'o' => 'Example',
                'description' => 'every attribute the class allows',
            ],
        ));

        self::assertCount(
            1,
            $this->ldapClient()->search(
                Operations::search(Filters::equal('cn', 'allmay'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
            ),
        );

        $this->ldapClient()->delete('cn=allmay,dc=foo,dc=bar');
    }

    public function testAddAcceptsEveryAttributeOrganizationalPersonPermits(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=allmayperson,dc=foo,dc=bar',
            [
                'objectClass' => 'organizationalPerson',
                'cn' => 'allmayperson',
                'sn' => 'Person',
                // Inherited from person.
                'userPassword' => 'secret',
                'seeAlso' => 'cn=admin,dc=foo,dc=bar',
                'description' => 'every attribute the class allows',
                'title' => 'Director',
                'x121Address' => '15 079 672 281',
                'registeredAddress' => '1234 Main St.$Anytown, CA 12345$USA',
                'destinationIndicator' => 'US',
                'preferredDeliveryMethod' => 'telephone $ physical',
                'telexNumber' => '12345$US$ACME',
                'teletexTerminalIdentifier' => 'terminal-1$graphic:on',
                'telephoneNumber' => '+1 555 555 1234',
                'internationalISDNNumber' => '15 079 672 281',
                'facsimileTelephoneNumber' => '+1 555 555 1234$fineResolution',
                'street' => '123 Example Way',
                'postOfficeBox' => '4242',
                'postalCode' => '12345',
                'postalAddress' => '1234 Main St.$Anytown, CA 12345$USA',
                'physicalDeliveryOfficeName' => 'Example Depot',
                'ou' => 'people',
                'st' => 'CA',
                'l' => 'Anytown',
                'c' => 'US',
            ],
        ));

        self::assertCount(
            1,
            $this->ldapClient()->search(
                Operations::search(Filters::equal('cn', 'allmayperson'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
            ),
        );

        $this->ldapClient()->delete('cn=allmayperson,dc=foo,dc=bar');
    }

    public function testAddAcceptsAUniqueMemberCarryingAnIdentifier(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=uidgroup,dc=foo,dc=bar',
            [
                'cn' => 'uidgroup',
                'uniqueMember' => "cn=user,dc=foo,dc=bar#'0101'B",
                'objectClass' => 'groupOfUniqueNames',
            ],
        ));

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'uniqueMember')
                ->base('cn=uidgroup,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ["cn=user,dc=foo,dc=bar#'0101'B"],
            $found->first()?->get('uniqueMember')?->getValues(),
        );

        $this->ldapClient()->delete('cn=uidgroup,dc=foo,dc=bar');
    }

    public function testAddRejectsAUniqueMemberWhoseNameIsNotADn(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=baduid,dc=foo,dc=bar',
            [
                'cn' => 'baduid',
                'uniqueMember' => "not a dn#'0101'B",
                'objectClass' => 'groupOfUniqueNames',
            ],
        ));
    }

    /**
     * RFC 4517 3.3.21 leaves '#' unescaped inside the name, so a tail that is not a bit string belongs to the DN.
     */
    public function testAddAcceptsAUniqueMemberWhoseTailIsNotABitString(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=notabitstring,dc=foo,dc=bar',
            [
                'cn' => 'notabitstring',
                'uniqueMember' => "cn=user,dc=foo,dc=bar#'0102'B",
                'objectClass' => 'groupOfUniqueNames',
            ],
        ));

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'uniqueMember')
                ->base('cn=notabitstring,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ["cn=user,dc=foo,dc=bar#'0102'B"],
            $found->first()?->get('uniqueMember')?->getValues(),
        );

        $this->ldapClient()->delete('cn=notabitstring,dc=foo,dc=bar');
    }

    public function testUniqueMemberMatchesOnTheNameAndTheIdentifierTogether(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=uidmatch,dc=foo,dc=bar',
            [
                'cn' => 'uidmatch',
                'uniqueMember' => "cn=user,dc=foo,dc=bar#'0101'B",
                'objectClass' => 'groupOfUniqueNames',
            ],
        ));

        $matches = fn(string $assertion): int => count($this->ldapClient()->search(
            Operations::search(Filters::equal('uniqueMember', $assertion))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        ));

        self::assertSame(
            1,
            $matches("cn=user,dc=foo,dc=bar#'0101'B"),
        );
        // RFC 4517 4.2.34: absent from one side and present on the other is a mismatch.
        self::assertSame(
            0,
            $matches('cn=user,dc=foo,dc=bar'),
        );
        self::assertSame(
            0,
            $matches("cn=user,dc=foo,dc=bar#'1111'B"),
        );

        $this->ldapClient()->delete('cn=uidmatch,dc=foo,dc=bar');
    }

    public function testModifyAddOfACaseVariantOnACaseExactAttributeIsANewValue(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=exactadd,dc=foo,dc=bar',
            [
                'cn' => 'exactadd',
                'sn' => 'Exact',
                'labeledURI' => 'http://Example.COM/A',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $this->ldapClient()->send(Operations::modify(
            'cn=exactadd,dc=foo,dc=bar',
            Change::add(new Attribute('labeledURI', 'http://example.com/a')),
        ));

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'labeledURI')
                ->base('cn=exactadd,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertCount(
            2,
            $found->first()?->get('labeledURI')?->getValues() ?? [],
        );

        $this->ldapClient()->delete('cn=exactadd,dc=foo,dc=bar');
    }

    public function testModifyDeleteOfACaseVariantOnACaseExactAttributeIsRefused(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=exactdel,dc=foo,dc=bar',
            [
                'cn' => 'exactdel',
                'sn' => 'Exact',
                'labeledURI' => 'http://Example.COM/A',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        try {
            $this->ldapClient()->send(Operations::modify(
                'cn=exactdel,dc=foo,dc=bar',
                Change::delete(new Attribute('labeledURI', 'http://example.com/a')),
            ));
            self::fail('Deleting a value the entry does not hold should have been rejected.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::NO_SUCH_ATTRIBUTE,
                $e->getCode(),
            );
        }

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'labeledURI')
                ->base('cn=exactdel,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ['http://Example.COM/A'],
            $found->first()?->get('labeledURI')?->getValues(),
        );

        $this->ldapClient()->delete('cn=exactdel,dc=foo,dc=bar');
    }

    public function testModifyDeleteOfACaseVariantOnACaseIgnoreAttributeSucceeds(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=ignoredel,dc=foo,dc=bar',
            [
                'cn' => 'ignoredel',
                'sn' => 'Ignore',
                'description' => 'Hello World',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $this->ldapClient()->send(Operations::modify(
            'cn=ignoredel,dc=foo,dc=bar',
            Change::delete(new Attribute('description', 'hello world')),
        ));

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'description')
                ->base('cn=ignoredel,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertNull($found->first()?->get('description'));

        $this->ldapClient()->delete('cn=ignoredel,dc=foo,dc=bar');
    }

    public function testModifyDeleteFoldsInsignificantSpaceOnACaseIgnoreAttribute(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=spacedel,dc=foo,dc=bar',
            [
                'cn' => 'spacedel',
                'sn' => 'Space',
                'description' => 'Hello World',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        // RFC 4518 §2.6.1 folds inner whitespace, so the doubled space names the stored value.
        $this->ldapClient()->send(Operations::modify(
            'cn=spacedel,dc=foo,dc=bar',
            Change::delete(new Attribute('description', 'Hello  World')),
        ));

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'description')
                ->base('cn=spacedel,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertNull($found->first()?->get('description'));

        $this->ldapClient()->delete('cn=spacedel,dc=foo,dc=bar');
    }

    public function testModifyDeletingEveryValueRemovesTheAttribute(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=dropmail,dc=foo,dc=bar',
            [
                'cn' => 'dropmail',
                'sn' => 'Drop',
                'mail' => ['one@foo.bar', 'two@foo.bar'],
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $this->ldapClient()->send(Operations::modify(
            'cn=dropmail,dc=foo,dc=bar',
            Change::delete(new Attribute('mail', 'one@foo.bar', 'two@foo.bar')),
        ));

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'mail')
                ->base('cn=dropmail,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertNull($found->first()?->get('mail'));

        $this->ldapClient()->delete('cn=dropmail,dc=foo,dc=bar');
    }

    public function testModifyDeletingTheLastValueOfARequiredAttributeIsRefused(): void
    {
        $this->authenticateAdmin();

        // Naming every value is the same removal as deleting the attribute outright, so sn must not survive empty.
        try {
            $this->ldapClient()->send(Operations::modify(
                'cn=user,dc=foo,dc=bar',
                Change::delete(new Attribute('sn', 'Admin')),
            ));
            self::fail('The schema violating modify should have been rejected.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::OBJECT_CLASS_VIOLATION,
                $e->getCode(),
            );
        }

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'sn')
                ->base('cn=user,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ['Admin'],
            $found->first()?->get('sn')?->getValues(),
        );
    }

    public function testRenameRemovingTheLastValueOfARequiredAttributeIsRefused(): void
    {
        $this->authenticateAdmin();

        // cn=user is an inetOrgPerson, so deleting the old cn leaves it without an attribute person requires.
        try {
            $this->ldapClient()->rename('cn=user,dc=foo,dc=bar', 'sn=Admin', true);
            self::fail('The schema violating rename should have been rejected.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::OBJECT_CLASS_VIOLATION,
                $e->getCode(),
            );
        }

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'cn')
                ->base('cn=user,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ['user'],
            $found->first()?->get('cn')?->getValues(),
        );
    }

    public function testRenameToAnUndefinedAttributeTypeIsRefused(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNDEFINED_ATTRIBUTE_TYPE);

        $this->ldapClient()->rename('cn=user,dc=foo,dc=bar', 'undefinedType=user', false);
    }

    public function testRenameToAnAttributeNoObjectClassPermitsIsRefused(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->ldapClient()->rename('cn=user,dc=foo,dc=bar', 'dc=user', false);
    }

    public function testRenameToANoUserModificationAttributeIsRefused(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->ldapClient()->rename('cn=user,dc=foo,dc=bar', 'hasSubordinates=TRUE', false);
    }

    public function testRenameDropsAnRdnAttributeLeftWithNoValues(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'employeeNumber=E1,dc=foo,dc=bar',
            [
                'cn' => 'pruneme',
                'sn' => 'Prune',
                'employeeNumber' => 'E1',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $this->ldapClient()->rename('employeeNumber=E1,dc=foo,dc=bar', 'cn=pruneme', true);

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'employeeNumber')
                ->base('cn=pruneme,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertNull($found->first()?->get('employeeNumber'));

        $this->ldapClient()->delete('cn=pruneme,dc=foo,dc=bar');
    }

    public function testRenameKeepsAnRdnAttributeHoldingOtherValues(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=keepme,dc=foo,dc=bar',
            ['cn' => ['keepme', 'kept'], 'sn' => 'Keep', 'objectClass' => 'inetOrgPerson'],
        ));

        $this->ldapClient()->rename('cn=keepme,dc=foo,dc=bar', 'cn=kept', true);

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'cn')
                ->base('cn=kept,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ['kept'],
            $found->first()?->get('cn')?->getValues(),
        );

        $this->ldapClient()->delete('cn=kept,dc=foo,dc=bar');
    }

    public function testRenameCanRespellTheRdnInADifferentCase(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=Recase,dc=foo,dc=bar',
            ['cn' => 'Recase', 'sn' => 'Recase', 'objectClass' => 'inetOrgPerson'],
        ));

        $this->ldapClient()->rename('cn=Recase,dc=foo,dc=bar', 'cn=recase', true);

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'cn')
                ->base('cn=recase,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ['recase'],
            $found->first()?->get('cn')?->getValues(),
        );

        $this->ldapClient()->delete('cn=recase,dc=foo,dc=bar');
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
}
