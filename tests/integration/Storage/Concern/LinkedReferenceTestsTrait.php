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
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;

/**
 * What only a backend keeping linked values as references to entries can answer.
 *
 * In memory storage keeps them as written, so it neither renames them with their target nor refuses a dangling one.
 */
trait LinkedReferenceTestsTrait
{
    use LinkedAttributeTestsTrait;

    public function testAMemberIsReadBackAsTheEntryItNamesIsStored(): void
    {
        $group = $this->seedGroup('link-spelling');

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::add('member', 'CN=Admin,  DC=Foo,DC=Bar'),
        ));

        self::assertEqualsCanonicalizing(
            [self::LINKED_USER, self::LINKED_ADMIN],
            $this->membersOf($group),
        );
    }

    public function testAMemberNamingAnEntryThatIsNotStoredIsRefused(): void
    {
        $group = $this->seedGroup('link-missing');

        $this->expectOperationCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::add('member', 'cn=nobody,dc=foo,dc=bar'),
        ));
    }

    public function testDeletingAMemberDropsItFromTheGroupsNamingIt(): void
    {
        $member = $this->seedReferencedMember('link-deleted-member');
        $group = $this->seedGroup('link-member-deleted', $member);

        $this->ldapClient()->delete($member);

        self::assertSame(
            [self::LINKED_USER],
            $this->membersOf($group),
        );
    }

    public function testRenamingAMemberShowsItUnderItsNewNameWithoutWritingTheGroup(): void
    {
        $member = $this->seedReferencedMember('link-renamed-member');
        $group = $this->seedGroup('link-member-renamed', $member);
        $before = $this->modifyTimestampOf($group);

        $this->ldapClient()->rename($member, 'cn=link-renamed-after');

        self::assertEqualsCanonicalizing(
            [self::LINKED_USER, 'cn=link-renamed-after,dc=foo,dc=bar'],
            $this->membersOf($group),
        );
        // The group was never written, so a rename cannot be told apart from no change at all by a consumer.
        self::assertSame(
            $before,
            $this->modifyTimestampOf($group),
        );
    }

    private function modifyTimestampOf(string $dn): ?string
    {
        return $this->ldapClient()
            ->read($dn, ['modifyTimestamp'])
            ?->get('modifyTimestamp')
            ?->firstValue();
    }

    private function seedReferencedMember(string $cn): string
    {
        $this->authenticateAdmin();
        $dn = "cn={$cn},dc=foo,dc=bar";

        $this->ldapClient()->create(Entry::fromArray(
            $dn,
            [
                'cn' => $cn,
                'objectClass' => 'inetOrgPerson',
                'sn' => $cn,
            ],
        ));

        return $dn;
    }
}
