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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Support\FreeDSx\Ldap\LdapBackendStorageCommand;

/**
 * Renaming and moving an entry that has subordinates, which travel with it (RFC 4511 §4.9).
 */
trait SubtreeMoveTestsTrait
{
    public function testRenameMovesTheSubordinatesOfTheEntry(): void
    {
        $this->seedSubtreeToMove();

        $this->asAdmin(fn(LdapClient $admin) => $admin->rename('ou=dept,dc=foo,dc=bar', 'ou=division', true));

        self::assertSame(
            [
                'cn=deep,cn=lead,ou=division,dc=foo,dc=bar',
                'cn=lead,ou=division,dc=foo,dc=bar',
                'ou=division,dc=foo,dc=bar',
            ],
            $this->dnsUnder('ou=division,dc=foo,dc=bar'),
        );

        $this->deleteSubtree('ou=division,dc=foo,dc=bar');
    }

    public function testRenamingASubtreeWithMultibyteDnsRekeysEveryDescendant(): void
    {
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray('ou=café,dc=foo,dc=bar', ['ou' => 'café', 'objectClass' => 'organizationalUnit']));
            $admin->create(Entry::fromArray('ou=münchen,ou=café,dc=foo,dc=bar', ['ou' => 'münchen', 'objectClass' => 'organizationalUnit']));
            $admin->create(Entry::fromArray(
                'cn=josé,ou=münchen,ou=café,dc=foo,dc=bar',
                ['cn' => 'josé', 'sn' => 'Ortiz', 'objectClass' => 'inetOrgPerson'],
            ));

            $admin->rename('ou=café,dc=foo,dc=bar', 'ou=zürich', true);
        });

        self::assertSame(
            [
                'cn=josé,ou=münchen,ou=zürich,dc=foo,dc=bar',
                'ou=münchen,ou=zürich,dc=foo,dc=bar',
                'ou=zürich,dc=foo,dc=bar',
            ],
            $this->dnsUnder('ou=zürich,dc=foo,dc=bar'),
        );

        $this->deleteSubtree('ou=zürich,dc=foo,dc=bar');
    }

    public function testRenameLeavesNothingBehindAtTheOldSubtree(): void
    {
        $this->seedSubtreeToMove();

        $this->asAdmin(fn(LdapClient $admin) => $admin->rename('ou=dept,dc=foo,dc=bar', 'ou=division', true));

        self::assertCount(
            0,
            $this->ldapClient()->search(
                Operations::search(Filters::equal('ou', 'dept'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
            ),
        );

        $this->deleteSubtree('ou=division,dc=foo,dc=bar');
    }

    public function testMoveRelocatesTheEntryAndItsSubordinatesUnderANewSuperior(): void
    {
        $this->seedSubtreeToMove();

        $this->asAdmin(fn(LdapClient $admin) => $admin->move('ou=dept,dc=foo,dc=bar', 'ou=people,dc=foo,dc=bar'));

        self::assertSame(
            [
                'cn=deep,cn=lead,ou=dept,ou=people,dc=foo,dc=bar',
                'cn=lead,ou=dept,ou=people,dc=foo,dc=bar',
                'ou=dept,ou=people,dc=foo,dc=bar',
            ],
            $this->dnsUnder('ou=dept,ou=people,dc=foo,dc=bar'),
        );

        $this->deleteSubtree('ou=dept,ou=people,dc=foo,dc=bar');
    }

    public function testMovedSubordinatesAreStillFoundByAnIndexedFilter(): void
    {
        $this->seedSubtreeToMove();

        $this->asAdmin(fn(LdapClient $admin) => $admin->rename('ou=dept,dc=foo,dc=bar', 'ou=division', true));

        $found = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'deep'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        self::assertSame(
            'cn=deep,cn=lead,ou=division,dc=foo,dc=bar',
            $found->first()?->getDn()->toString(),
        );

        $this->deleteSubtree('ou=division,dc=foo,dc=bar');
    }

    public function testMoveIntoItsOwnSubtreeIsRefused(): void
    {
        $this->seedSubtreeToMove();
        $this->authenticateAdmin();

        try {
            $this->ldapClient()->move('ou=dept,dc=foo,dc=bar', 'cn=lead,ou=dept,dc=foo,dc=bar');
            self::fail('Moving an entry beneath itself should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::UNWILLING_TO_PERFORM,
                $e->getCode(),
            );
        }

        $this->deleteSubtree('ou=dept,dc=foo,dc=bar');
    }

    public function testRenamingASubtreeIsRefusedForANormalUser(): void
    {
        $this->seedSubtreeToMove();

        $this->authenticateUser();

        try {
            $this->ldapClient()->rename('ou=dept,dc=foo,dc=bar', 'ou=division', true);
            self::fail('A subtree rename should not be permitted under the default ACL.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        self::assertSame(
            [
                'cn=deep,cn=lead,ou=dept,dc=foo,dc=bar',
                'cn=lead,ou=dept,dc=foo,dc=bar',
                'ou=dept,dc=foo,dc=bar',
            ],
            $this->dnsUnder('ou=dept,dc=foo,dc=bar'),
        );

        $this->deleteSubtree('ou=dept,dc=foo,dc=bar');
    }

    public function testAnIdentityGrantedModifyDnCanRenameASubtree(): void
    {
        $this->seedMover();
        $this->seedSubtreeToMove();

        $this->authenticateMover();
        $this->ldapClient()->rename('ou=dept,dc=foo,dc=bar', 'ou=division', true);

        self::assertSame(
            [
                'cn=deep,cn=lead,ou=division,dc=foo,dc=bar',
                'cn=lead,ou=division,dc=foo,dc=bar',
                'ou=division,dc=foo,dc=bar',
            ],
            $this->dnsUnder('ou=division,dc=foo,dc=bar'),
        );

        $this->deleteSubtree('ou=division,dc=foo,dc=bar');
        $this->asAdmin(fn(LdapClient $admin) => $admin->delete(LdapBackendStorageCommand::MOVER_DN));
    }

    public function testRenamingInPlaceIsAllowedInsideAPinnedContainer(): void
    {
        $this->seedMover();
        $this->seedPinnedContainer();

        $this->authenticateMover();
        $this->ldapClient()->rename('cn=held,ou=pinned,dc=foo,dc=bar', 'cn=renamed', true);

        self::assertSame(
            [
                'cn=renamed,ou=pinned,dc=foo,dc=bar',
                'ou=pinned,dc=foo,dc=bar',
            ],
            $this->dnsUnder(LdapBackendStorageCommand::PINNED_CONTAINER_DN),
        );

        $this->cleanUpRelocationFixtures();
    }

    public function testMovingOutOfAPinnedContainerIsRefused(): void
    {
        $this->seedMover();
        $this->seedPinnedContainer();

        $this->authenticateMover();

        try {
            $this->ldapClient()->move('cn=held,ou=pinned,dc=foo,dc=bar', 'dc=foo,dc=bar');
            self::fail('Moving out of a pinned container should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        $this->authenticateUser();
        self::assertNotNull($this->ldapClient()->read('cn=held,ou=pinned,dc=foo,dc=bar'));

        $this->cleanUpRelocationFixtures();
    }

    public function testMovingThePinnedContainerItselfIsRefused(): void
    {
        $this->seedMover();
        $this->seedPinnedContainer();
        $this->asAdmin(fn(LdapClient $admin) => $admin->create(Entry::fromArray(
            'ou=elsewhere,dc=foo,dc=bar',
            ['ou' => 'elsewhere', 'objectClass' => 'organizationalUnit'],
        )));

        $this->authenticateMover();

        try {
            $this->ldapClient()->move(
                LdapBackendStorageCommand::PINNED_CONTAINER_DN,
                'ou=elsewhere,dc=foo,dc=bar',
            );
            self::fail('Moving the pinned container itself should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        $this->authenticateUser();
        self::assertNotNull($this->ldapClient()->read('cn=held,ou=pinned,dc=foo,dc=bar'));

        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('ou=elsewhere,dc=foo,dc=bar'));
        $this->cleanUpRelocationFixtures();
    }

    public function testMovingAnUnguardedContainerIsAllowed(): void
    {
        $this->seedMover();
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                'ou=loosecontainer,dc=foo,dc=bar',
                ['ou' => 'loosecontainer', 'objectClass' => 'organizationalUnit'],
            ));
            $admin->create(Entry::fromArray(
                'ou=elsewhere,dc=foo,dc=bar',
                ['ou' => 'elsewhere', 'objectClass' => 'organizationalUnit'],
            ));
        });

        $this->authenticateMover();
        $this->ldapClient()->move('ou=loosecontainer,dc=foo,dc=bar', 'ou=elsewhere,dc=foo,dc=bar');

        $this->authenticateUser();
        self::assertNotNull($this->ldapClient()->read('ou=loosecontainer,ou=elsewhere,dc=foo,dc=bar'));

        $this->asAdmin(function (LdapClient $admin): void {
            $admin->delete('ou=loosecontainer,ou=elsewhere,dc=foo,dc=bar');
            $admin->delete('ou=elsewhere,dc=foo,dc=bar');
            $admin->delete(LdapBackendStorageCommand::MOVER_DN);
        });
    }

    public function testMovingIntoASealedContainerIsRefused(): void
    {
        $this->seedMover();
        $this->seedPinnedContainer();
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                LdapBackendStorageCommand::SEALED_CONTAINER_DN,
                ['ou' => 'sealed', 'objectClass' => 'organizationalUnit'],
            ));
            $admin->create(Entry::fromArray(
                'cn=loose,dc=foo,dc=bar',
                ['cn' => 'loose', 'sn' => 'Loose', 'objectClass' => 'inetOrgPerson'],
            ));
        });

        $this->authenticateMover();

        try {
            $this->ldapClient()->move('cn=loose,dc=foo,dc=bar', LdapBackendStorageCommand::SEALED_CONTAINER_DN);
            self::fail('Moving into a sealed container should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        $this->authenticateUser();
        self::assertNotNull($this->ldapClient()->read('cn=loose,dc=foo,dc=bar'));

        $this->asAdmin(function (LdapClient $admin): void {
            $admin->delete('cn=loose,dc=foo,dc=bar');
            $admin->delete(LdapBackendStorageCommand::SEALED_CONTAINER_DN);
        });
        $this->cleanUpRelocationFixtures();
    }

    /**
     * Created per test rather than seeded, so the shared fixture's entry counts stay as every other case expects.
     */
    private function seedMover(): void
    {
        $this->asAdmin(fn(LdapClient $admin) => $admin->create(Entry::fromArray(
            LdapBackendStorageCommand::MOVER_DN,
            [
                'cn' => 'mover',
                'sn' => 'Mover',
                'userPassword' => LdapBackendStorageCommand::MOVER_PASSWORD,
                'objectClass' => 'inetOrgPerson',
            ],
        )));
    }

    private function authenticateMover(): void
    {
        $this->ldapClient()->bind(
            LdapBackendStorageCommand::MOVER_DN,
            LdapBackendStorageCommand::MOVER_PASSWORD,
        );
    }

    /**
     * The container cn=mover is denied moving entries out of, holding one entry to try it with.
     */
    private function seedPinnedContainer(): void
    {
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                LdapBackendStorageCommand::PINNED_CONTAINER_DN,
                ['ou' => 'pinned', 'objectClass' => 'organizationalUnit'],
            ));
            $admin->create(Entry::fromArray(
                'cn=held,ou=pinned,dc=foo,dc=bar',
                ['cn' => 'held', 'sn' => 'Held', 'objectClass' => 'inetOrgPerson'],
            ));
        });
    }

    private function cleanUpRelocationFixtures(): void
    {
        $this->deleteSubtree(LdapBackendStorageCommand::PINNED_CONTAINER_DN);
        $this->asAdmin(fn(LdapClient $admin) => $admin->delete(LdapBackendStorageCommand::MOVER_DN));
    }

    /**
     * A three-level subtree, so a rename has to reach past the entries directly beneath the base.
     */
    private function seedSubtreeToMove(): void
    {
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                'ou=dept,dc=foo,dc=bar',
                ['ou' => 'dept', 'objectClass' => 'organizationalUnit'],
            ));
            $admin->create(Entry::fromArray(
                'cn=lead,ou=dept,dc=foo,dc=bar',
                ['cn' => 'lead', 'sn' => 'Lead', 'objectClass' => 'inetOrgPerson'],
            ));
            $admin->create(Entry::fromArray(
                'cn=deep,cn=lead,ou=dept,dc=foo,dc=bar',
                ['cn' => 'deep', 'sn' => 'Deep', 'objectClass' => 'inetOrgPerson'],
            ));
        });
    }

    /**
     * @return list<string>
     */
    private function dnsUnder(string $baseDn): array
    {
        $dns = [];

        foreach ($this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base($baseDn)
                ->useSubtreeScope(),
        ) as $entry) {
            $dns[] = $entry->getDn()->toString();
        }
        sort($dns);

        return $dns;
    }

    /**
     * Deepest first, since an entry holding subordinates cannot be deleted.
     */
    private function deleteSubtree(string $baseDn): void
    {
        $this->asAdmin(function (LdapClient $admin) use ($baseDn): void {
            $dns = $this->dnsUnder($baseDn);
            usort(
                $dns,
                static fn(string $a, string $b): int => substr_count($b, ',') <=> substr_count($a, ','),
            );

            foreach ($dns as $dn) {
                $admin->delete($dn);
            }
        });
    }
}
