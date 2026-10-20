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
use FreeDSx\Ldap\Control\ReadEntry\PostReadResponseControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Filters;

/**
 * Reads and writes of the attributes whose values name other entries.
 */
trait LinkedAttributeTestsTrait
{
    private const LINKED_USER = 'cn=user,dc=foo,dc=bar';

    private const LINKED_ADMIN = 'cn=admin,dc=foo,dc=bar';

    private const LINKED_ALICE = 'cn=alice,ou=people,dc=foo,dc=bar';

    private const LINKED_NOSN = 'cn=nosn,dc=foo,dc=bar';

    public function testAddingAMemberKeepsThoseAlreadyLinked(): void
    {
        $group = $this->seedGroup('link-add');

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::add(
                'member',
                self::LINKED_ADMIN,
            ),
        ));

        self::assertEqualsCanonicalizing(
            [self::LINKED_USER, self::LINKED_ADMIN],
            $this->membersOf($group),
        );
    }

    public function testDeletingAMemberLeavesTheRestLinked(): void
    {
        $group = $this->seedGroup('link-delete');

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::add(
                'member',
                self::LINKED_ADMIN,
            ),
        ));
        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::delete(
                'member',
                self::LINKED_USER,
            ),
        ));

        self::assertSame(
            [self::LINKED_ADMIN],
            $this->membersOf($group),
        );
    }

    public function testDeletingAMemberInAnotherSpellingRemovesIt(): void
    {
        $group = $this->seedGroup(
            'link-delete-spelling',
            self::LINKED_ADMIN,
        );

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::delete(
                'member',
                'CN=User, DC=foo, DC=bar',
            ),
        ));

        self::assertSame(
            [self::LINKED_ADMIN],
            $this->membersOf($group),
        );
    }

    public function testAddingAndDeletingAMemberInOneModifyKeepsTheOthers(): void
    {
        $group = $this->seedGroup(
            'link-add-delete',
            self::LINKED_ADMIN,
        );

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::add(
                'member',
                self::LINKED_ALICE,
            ),
            Change::delete(
                'member',
                self::LINKED_ALICE,
            ),
        ));

        self::assertEqualsCanonicalizing(
            [self::LINKED_USER, self::LINKED_ADMIN],
            $this->membersOf($group),
        );
    }

    public function testDeletingAndAddingAMemberInOneModifyKeepsIt(): void
    {
        $group = $this->seedGroup(
            'link-delete-add',
            self::LINKED_ADMIN,
        );

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::delete(
                'member',
                self::LINKED_USER,
            ),
            Change::add(
                'member',
                self::LINKED_USER,
            ),
        ));

        self::assertEqualsCanonicalizing(
            [self::LINKED_USER, self::LINKED_ADMIN],
            $this->membersOf($group),
        );
    }

    public function testDeletingAMemberTwiceInOneModifyIsRefused(): void
    {
        $group = $this->seedGroup('link-delete-twice');

        $this->expectOperationCode(ResultCode::NO_SUCH_ATTRIBUTE);

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::delete(
                'member',
                self::LINKED_USER,
            ),
            Change::delete(
                'member',
                self::LINKED_USER,
            ),
        ));
    }

    public function testALinkedValueTheObjectClassesDoNotPermitIsRefused(): void
    {
        $person = $this->seedPerson('link-person');

        $this->expectOperationCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->ldapClient()->send(Operations::modify(
            $person,
            Change::add(
                'member',
                self::LINKED_ADMIN,
            ),
        ));
    }

    public function testALinkedValueTheObjectClassesDoNotPermitIsRefusedWhenAControlReadsTheEntry(): void
    {
        $person = $this->seedPerson('link-person-read');

        $this->expectOperationCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->ldapClient()->send(
            Operations::modify(
                $person,
                Change::add(
                    'member',
                    self::LINKED_ADMIN,
                ),
            ),
            Controls::preRead('cn'),
        );
    }

    public function testAUserAddingAPasswordPolicyPointerIsRefused(): void
    {
        $person = $this->seedPerson('link-policy');

        $this->expectOperationCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->ldapClient()->send(Operations::modify(
            $person,
            Change::add(
                'pwdPolicySubentry',
                self::LINKED_ADMIN,
            ),
        ));
    }

    public function testDroppingTheClassThatPermitsAKeptLinkedValueIsRefused(): void
    {
        $person = $this->seedPerson(
            'link-classes',
            ['extensibleObject'],
            ['member' => self::LINKED_USER],
        );

        $this->expectOperationCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->ldapClient()->send(Operations::modify(
            $person,
            Change::delete(
                'objectClass',
                'extensibleObject',
            ),
            Change::add(
                'seeAlso',
                self::LINKED_ADMIN,
            ),
        ));
    }

    public function testReplacingTheMembersWritesThemWhole(): void
    {
        $group = $this->seedGroup('link-replace');

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::replace(
                'member',
                self::LINKED_ADMIN,
            ),
        ));

        self::assertSame(
            [self::LINKED_ADMIN],
            $this->membersOf($group),
        );
    }

    public function testAddingAMemberAlreadyLinkedIsRefused(): void
    {
        $group = $this->seedGroup('link-duplicate');

        $this->expectOperationCode(ResultCode::ATTRIBUTE_OR_VALUE_EXISTS);

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::add(
                'member',
                self::LINKED_USER,
            ),
        ));
    }

    public function testDeletingAMemberThatIsNotLinkedIsRefused(): void
    {
        $group = $this->seedGroup('link-absent');

        $this->expectOperationCode(ResultCode::NO_SUCH_ATTRIBUTE);

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::delete(
                'member',
                self::LINKED_ADMIN,
            ),
        ));
    }

    public function testTheSameMemberGivenTwiceIsRefused(): void
    {
        $group = $this->seedGroup('link-twice');

        $this->expectOperationCode(ResultCode::ATTRIBUTE_OR_VALUE_EXISTS);

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::add(
                'member',
                self::LINKED_ADMIN,
                self::LINKED_ADMIN,
            ),
        ));
    }

    public function testAMemberThatIsNotADistinguishedNameIsRefused(): void
    {
        $group = $this->seedGroup('link-syntax');

        $this->expectOperationCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::add(
                'member',
                'not a dn',
            ),
        ));
    }

    public function testARefusedMemberChangeLeavesTheGroupAlone(): void
    {
        $group = $this->seedGroup('link-refused');

        try {
            $this->ldapClient()->send(Operations::modify(
                $group,
                Change::add(
                    'member',
                    self::LINKED_USER,
                ),
            ));
        } catch (OperationException) {
        }

        self::assertSame(
            [self::LINKED_USER],
            $this->membersOf($group),
        );
    }

    public function testALinkedAttributeIsReturnedUnderItsSchemaName(): void
    {
        $person = $this->seedPerson(
            'link-name',
            [],
            ['SEEALSO' => self::LINKED_ADMIN],
        );

        self::assertSame(
            ['seeAlso'],
            $this->attributeNamesOf($this->ldapClient()->read($person, ['seeAlso'])),
        );
    }

    public function testAValueAddedToALinkedAttributeIsReturnedUnderItsSchemaName(): void
    {
        $person = $this->seedPerson(
            'link-name-add',
            [],
            ['seeAlso' => self::LINKED_ADMIN],
        );

        $this->ldapClient()->send(Operations::modify(
            $person,
            Change::add(
                'SEEALSO',
                self::LINKED_USER,
            ),
        ));

        self::assertSame(
            ['seeAlso'],
            $this->attributeNamesOf($this->ldapClient()->read($person, ['seeAlso'])),
        );
    }

    public function testAChangeLeavingALinkedAttributeAloneKeepsItsSchemaName(): void
    {
        $person = $this->seedPerson(
            'link-name-kept',
            [],
            ['seeAlso' => self::LINKED_ADMIN],
        );

        $this->ldapClient()->send(Operations::modify(
            $person,
            Change::replace(
                'description',
                'Renamed',
            ),
        ));

        self::assertSame(
            ['seeAlso'],
            $this->attributeNamesOf($this->ldapClient()->read($person, ['seeAlso'])),
        );
    }

    public function testASliceOfALinkedAttributeIsNamedUnderItsSchemaName(): void
    {
        $person = $this->seedPerson(
            'link-name-slice',
            [],
            ['seeAlso' => [self::LINKED_ADMIN, self::LINKED_USER]],
        );

        self::assertSame(
            ['seeAlso;range=1-*'],
            $this->attributeNamesOf($this->ldapClient()->read($person, ['seeAlso;range=1-*'])),
        );
    }

    public function testAPostReadOfAnAddNamesALinkedAttributeAsTheSchemaDoes(): void
    {
        $this->authenticateAdmin();

        $response = $this->ldapClient()->sendAndReceive(
            Operations::add(Entry::fromArray(
                'cn=link-name-post-add,dc=foo,dc=bar',
                [
                    'cn' => 'link-name-post-add',
                    'sn' => 'link-name-post-add',
                    'objectClass' => 'person',
                    'SEEALSO' => self::LINKED_ADMIN,
                ],
            )),
            Controls::postRead('seeAlso'),
        );

        self::assertSame(
            ['seeAlso'],
            $this->attributeNamesOf($this->postReadOf($response)),
        );
    }

    public function testAPostReadOfAModifyNamesALinkedAttributeAsTheSchemaDoes(): void
    {
        $person = $this->seedPerson('link-name-post-modify');

        $response = $this->ldapClient()->sendAndReceive(
            Operations::modify(
                $person,
                Change::replace(
                    'SEEALSO',
                    self::LINKED_ADMIN,
                ),
            ),
            Controls::postRead('seeAlso'),
        );

        self::assertSame(
            ['seeAlso'],
            $this->attributeNamesOf($this->postReadOf($response)),
        );
    }

    public function testASliceOfAMembershipIsReturnedUnderTheRangeItHolds(): void
    {
        // Four members, so the slice asked for stops short of the end and is named for where it stops.
        $group = $this->seedGroup(
            'range-slice',
            self::LINKED_ADMIN,
            self::LINKED_ALICE,
            self::LINKED_NOSN,
        );

        $entry = $this->ldapClient()->read($group, ['member;range=1-2']);

        self::assertSame(
            ['member;range=1-2'],
            $this->attributeNamesOf($entry),
        );
        self::assertCount(
            2,
            $entry?->get('member;range=1-2')?->getValues() ?? [],
        );
    }

    public function testASliceIsServedHoweverTheRangeOptionIsSpelled(): void
    {
        $group = $this->seedGroup(
            'range-spelling',
            self::LINKED_ADMIN,
            self::LINKED_ALICE,
            self::LINKED_NOSN,
        );

        self::assertSame(
            ['member;range=1-2'],
            $this->attributeNamesOf($this->ldapClient()->read($group, ['member;Range=1-2'])),
        );
    }

    public function testASliceReachingTheEndIsNamedToTheEnd(): void
    {
        $group = $this->seedGroup(
            'range-end',
            self::LINKED_ADMIN,
            self::LINKED_ALICE,
        );

        self::assertSame(
            ['member;range=2-*'],
            $this->attributeNamesOf($this->ldapClient()->read($group, ['member;range=2-*'])),
        );
    }

    public function testAWholeMembershipAskedForAsASliceKeepsItsPlainName(): void
    {
        $group = $this->seedGroup('range-whole', self::LINKED_ADMIN);

        self::assertSame(
            ['member'],
            $this->attributeNamesOf($this->ldapClient()->read($group, ['member;range=0-*'])),
        );
    }

    public function testASubtreeSearchSlicesEveryEntryItReturns(): void
    {
        $group = $this->seedGroup(
            'range-subtree',
            self::LINKED_ADMIN,
            self::LINKED_ALICE,
            self::LINKED_NOSN,
        );

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'range-subtree'), 'member;range=1-2')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $entries);

        foreach ($entries as $entry) {
            self::assertSame($group, $entry->getDn()->toString());
            self::assertSame(
                ['member;range=1-2'],
                $this->attributeNamesOf($entry),
            );
        }
    }

    public function testARangeOnAnAttributeTheServerDoesNotRangeIsRefused(): void
    {
        $group = $this->seedGroup('range-unranged');

        $this->expectOperationCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->ldapClient()->read($group, ['cn;range=0-1']);
    }

    public function testARangeThatCannotBeServedIsRefused(): void
    {
        $group = $this->seedGroup('range-bad');

        $this->expectOperationCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->ldapClient()->read($group, ['member;range=9-2']);
    }

    /**
     * @return list<string>
     */
    private function attributeNamesOf(?Entry $entry): array
    {
        $names = [];

        foreach ($entry?->getAttributes() ?? [] as $attribute) {
            $names[] = $attribute->getDescription();
        }

        return $names;
    }

    /**
     * A group of its own per test, since the server is shared across the class.
     */
    private function seedGroup(
        string $cn,
        string ...$members,
    ): string {
        $this->authenticateAdmin();
        $dn = "cn={$cn},dc=foo,dc=bar";

        $this->ldapClient()->create(Entry::fromArray(
            $dn,
            [
                'cn' => $cn,
                'objectClass' => 'groupOfNames',
                'member' => [self::LINKED_USER, ...$members],
            ],
        ));

        return $dn;
    }

    /**
     * @param list<string> $auxiliaries
     * @param array<string, string|list<string>> $attributes
     */
    private function seedPerson(
        string $cn,
        array $auxiliaries = [],
        array $attributes = [],
    ): string {
        $this->authenticateAdmin();
        $dn = "cn={$cn},dc=foo,dc=bar";

        $this->ldapClient()->create(Entry::fromArray(
            $dn,
            [
                'cn' => $cn,
                'sn' => $cn,
                'objectClass' => ['person', ...$auxiliaries],
                ...$attributes,
            ],
        ));

        return $dn;
    }

    /**
     * @return list<string>
     */
    private function membersOf(string $dn): array
    {
        return array_values(
            $this->ldapClient()
                ->read($dn, ['member'])
                ?->get('member')
                ?->getValues() ?? [],
        );
    }

    private function postReadOf(LdapMessageResponse $response): ?Entry
    {
        $control = $response->controls()->get(Control::OID_POST_READ);

        return $control instanceof PostReadResponseControl
            ? $control->getEntry()
            : null;
    }

    private function expectOperationCode(int $code): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode($code);
    }
}
