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

use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;

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

        $this->asAdmin(fn(LdapClient $admin) => $admin->send(Operations::modify(
            $group,
            Change::add('member', 'CN=Admin,  DC=Foo,DC=Bar'),
        )));

        self::assertEqualsCanonicalizing(
            [self::LINKED_USER, self::LINKED_ADMIN],
            $this->membersOf($group),
        );
    }

    public function testAMemberNamingAnEntryThatIsNotStoredIsRefused(): void
    {
        $group = $this->seedGroup('link-missing');
        $this->authenticateAdmin();

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

        $this->asAdmin(fn(LdapClient $admin) => $admin->delete($member));

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

        $this->asAdmin(fn(LdapClient $admin) => $admin->rename(
            $member,
            'cn=link-renamed-after',
        ));

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

    public function testRenamingAnEntryKeepsItsLinkIntoItsOwnSubtree(): void
    {
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                'ou=link-moved-team,dc=foo,dc=bar',
                [
                    'objectClass' => 'organizationalUnit',
                    'ou' => 'link-moved-team',
                ],
            ));
            $admin->create(Entry::fromArray(
                'cn=lead,ou=link-moved-team,dc=foo,dc=bar',
                [
                    'cn' => 'lead',
                    'objectClass' => 'person',
                    'sn' => 'lead',
                ],
            ));
            $admin->send(Operations::modify(
                'ou=link-moved-team,dc=foo,dc=bar',
                Change::add(
                    'seeAlso',
                    'cn=lead,ou=link-moved-team,dc=foo,dc=bar',
                ),
            ));
            $admin->rename(
                'ou=link-moved-team,dc=foo,dc=bar',
                'ou=link-moved-crew',
            );
        });

        self::assertSame(
            ['cn=lead,ou=link-moved-crew,dc=foo,dc=bar'],
            $this->seeAlsoOf('ou=link-moved-crew,dc=foo,dc=bar'),
        );
    }

    public function testRenamingAnEntryKeepsItsLinkToItself(): void
    {
        $this->seedLinkedToItselfAndRenamed(
            'link-self',
            'cn=link-self-renamed',
        );

        self::assertSame(
            ['cn=link-self-renamed,dc=foo,dc=bar'],
            $this->seeAlsoOf('cn=link-self-renamed,dc=foo,dc=bar'),
        );
    }

    public function testAnEntryAddedAtARenamedEntrysOldNameIsNotLinkedInItsPlace(): void
    {
        $this->seedLinkedToItselfAndRenamed(
            'link-old-name',
            'cn=link-new-name',
        );

        $this->seedPerson('link-old-name');

        self::assertSame(
            ['cn=link-new-name,dc=foo,dc=bar'],
            $this->seeAlsoOf('cn=link-new-name,dc=foo,dc=bar'),
        );
    }

    public function testARenamesPostReadShowsItsLinksIntoItsOwnSubtreeAtTheirNewDns(): void
    {
        $team = 'ou=link-post-team,dc=foo,dc=bar';
        $lead = 'cn=lead,' . $team;

        $response = $this->asAdmin(function (LdapClient $admin) use ($team, $lead): LdapMessageResponse {
            $admin->create(Entry::fromArray(
                $team,
                [
                    'objectClass' => 'organizationalUnit',
                    'ou' => 'link-post-team',
                ],
            ));
            $admin->create(Entry::fromArray(
                $lead,
                [
                    'cn' => 'lead',
                    'objectClass' => 'person',
                    'sn' => 'lead',
                ],
            ));
            $admin->send(Operations::modify(
                $team,
                Change::add(
                    'seeAlso',
                    $team,
                    $lead,
                ),
            ));

            return $admin->sendAndReceive(
                Operations::rename(
                    $team,
                    'ou=link-post-crew',
                    true,
                ),
                Controls::postRead('seeAlso'),
            );
        });

        self::assertEqualsCanonicalizing(
            [
                'ou=link-post-crew,dc=foo,dc=bar',
                'cn=lead,ou=link-post-crew,dc=foo,dc=bar',
            ],
            $this->postReadOf($response)?->get('seeAlso')?->getValues(),
        );
    }

    private function seedLinkedToItselfAndRenamed(
        string $cn,
        string $newRdn,
    ): void {
        $person = $this->seedPerson($cn);

        $this->asAdmin(function (LdapClient $admin) use ($person, $newRdn): void {
            $admin->send(Operations::modify(
                $person,
                Change::add(
                    'seeAlso',
                    $person,
                ),
            ));
            $admin->rename(
                $person,
                $newRdn,
            );
        });
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
        $dn = "cn={$cn},dc=foo,dc=bar";

        $this->asAdmin(fn(LdapClient $admin) => $admin->create(Entry::fromArray(
            $dn,
            [
                'cn' => $cn,
                'objectClass' => 'inetOrgPerson',
                'sn' => $cn,
            ],
        )));

        return $dn;
    }
}
