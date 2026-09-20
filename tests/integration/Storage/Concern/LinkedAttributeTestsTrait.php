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

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;

/**
 * Reads and writes of the attributes whose values name other entries.
 */
trait LinkedAttributeTestsTrait
{
    private const LINKED_USER = 'cn=user,dc=foo,dc=bar';

    private const LINKED_ADMIN = 'cn=admin,dc=foo,dc=bar';

    public function testAddingAMemberKeepsThoseAlreadyLinked(): void
    {
        $group = $this->seedGroup('link-add');

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::add('member', self::LINKED_ADMIN),
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
            Change::add('member', self::LINKED_ADMIN),
        ));
        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::delete('member', self::LINKED_USER),
        ));

        self::assertSame(
            [self::LINKED_ADMIN],
            $this->membersOf($group),
        );
    }

    public function testReplacingTheMembersWritesThemWhole(): void
    {
        $group = $this->seedGroup('link-replace');

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::replace('member', self::LINKED_ADMIN),
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
            Change::add('member', self::LINKED_USER),
        ));
    }

    public function testDeletingAMemberThatIsNotLinkedIsRefused(): void
    {
        $group = $this->seedGroup('link-absent');

        $this->expectOperationCode(ResultCode::NO_SUCH_ATTRIBUTE);

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::delete('member', self::LINKED_ADMIN),
        ));
    }

    public function testTheSameMemberGivenTwiceIsRefused(): void
    {
        $group = $this->seedGroup('link-twice');

        $this->expectOperationCode(ResultCode::ATTRIBUTE_OR_VALUE_EXISTS);

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::add('member', self::LINKED_ADMIN, self::LINKED_ADMIN),
        ));
    }

    public function testAMemberThatIsNotADistinguishedNameIsRefused(): void
    {
        $group = $this->seedGroup('link-syntax');

        $this->expectOperationCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::add('member', 'not a dn'),
        ));
    }

    public function testARefusedMemberChangeLeavesTheGroupAlone(): void
    {
        $group = $this->seedGroup('link-refused');

        try {
            $this->ldapClient()->send(Operations::modify(
                $group,
                Change::add('member', self::LINKED_USER),
            ));
        } catch (OperationException) {
        }

        self::assertSame(
            [self::LINKED_USER],
            $this->membersOf($group),
        );
    }

    /**
     * A group of its own per test, since the server is shared across the class.
     */
    private function seedGroup(string $cn): string
    {
        $this->authenticateAdmin();
        $dn = "cn={$cn},dc=foo,dc=bar";

        $this->ldapClient()->create(Entry::fromArray(
            $dn,
            [
                'cn' => $cn,
                'objectClass' => 'groupOfNames',
                'member' => self::LINKED_USER,
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

    private function expectOperationCode(int $code): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode($code);
    }
}
