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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern\Write;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The schema held against what an add, modify, or rename leaves behind.
 */
trait WriteSchemaTestsTrait
{
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

    #[DataProvider('rdnValueFailingItsSyntaxProvider')]
    public function testAddIsRefusedWhenAnRdnValueFailsItsSyntax(Entry $entry): void
    {
        $this->authenticateAdmin();

        try {
            $this->ldapClient()->create($entry);
            self::fail('An add whose RDN value fails its syntax should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INVALID_DN_SYNTAX,
                $e->getCode(),
            );
        }
    }

    /**
     * @return iterable<string, array{Entry}>
     */
    public static function rdnValueFailingItsSyntaxProvider(): iterable
    {
        yield 'an empty directory string' => [
            new Entry(
                'cn=,dc=foo,dc=bar',
                new Attribute('objectClass', 'top', 'person'),
                new Attribute('sn', 'Empty'),
            ),
        ];
        yield 'a country code of three letters' => [
            new Entry(
                'c=USA,dc=foo,dc=bar',
                new Attribute('objectClass', 'top', 'country'),
            ),
        ];
    }

    public function testRenameIsRefusedWhenTheNewRdnValueFailsItsSyntax(): void
    {
        $this->authenticateAdmin();

        try {
            $this->ldapClient()->rename(
                'cn=user,dc=foo,dc=bar',
                'cn=',
                true,
            );
            self::fail('A rename onto an RDN value failing its syntax should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INVALID_DN_SYNTAX,
                $e->getCode(),
            );
        }

        self::assertNotNull($this->ldapClient()->read('cn=user,dc=foo,dc=bar'));
    }

    public function testAddRejectsAnUndefinedObjectClassAndStoresNothing(): void
    {
        $this->authenticateAdmin();

        try {
            $this->ldapClient()->create(new Entry(
                'cn=undefinedclass,dc=foo,dc=bar',
                new Attribute('objectClass', 'top', 'person', 'xNoSuchClass'),
                new Attribute('cn', 'undefinedclass'),
                new Attribute('sn', 'Undefined'),
            ));
            self::fail('An add carrying an undefined object class should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::OBJECT_CLASS_VIOLATION,
                $e->getCode(),
            );
        }

        self::assertNull($this->ldapClient()->read('cn=undefinedclass,dc=foo,dc=bar'));
    }

    public function testModifyRejectsAddingAnUndefinedObjectClass(): void
    {
        $this->authenticateAdmin();

        try {
            $this->ldapClient()->send(Operations::modify(
                'cn=user,dc=foo,dc=bar',
                Change::add(new Attribute('objectClass', '1.2.3.4.5.6.7.8')),
            ));
            self::fail('A modify adding an undefined object class should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::OBJECT_CLASS_VIOLATION,
                $e->getCode(),
            );
        }

        self::assertNotContains(
            '1.2.3.4.5.6.7.8',
            $this->ldapClient()->read(
                'cn=user,dc=foo,dc=bar',
                ['objectClass'],
            )?->get('objectClass')?->getValues() ?? [],
        );
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

    /**
     * RFC 4517 3.3.4 makes a country string exactly two printable characters.
     */
    public function testAddRejectsACountryCodeThatIsNotTwoCharacters(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->ldapClient()->create(Entry::fromArray(
            'o=badcountry,dc=foo,dc=bar',
            [
                'o' => 'badcountry',
                'c' => 'UnitedStates',
                'objectClass' => 'organization',
            ],
        ));
    }

    public function testAddAcceptsATwoCharacterCountryCode(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'o=goodcountry,dc=foo,dc=bar',
            [
                'o' => 'goodcountry',
                'c' => 'US',
                'objectClass' => 'organization',
            ],
        ));

        $found = $this->ldapClient()->read('o=goodcountry,dc=foo,dc=bar', ['c']);

        self::assertSame(
            ['US'],
            $found?->get('c')?->getValues(),
        );

        $this->ldapClient()->delete('o=goodcountry,dc=foo,dc=bar');
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
}
