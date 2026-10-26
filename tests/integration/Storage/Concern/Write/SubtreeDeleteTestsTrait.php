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

use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use Tests\Support\FreeDSx\Ldap\LdapBackendStorageCommand;

/**
 * Deleting an entry with everything beneath it, which the subtree delete control's grant on that entry authorizes.
 */
trait SubtreeDeleteTestsTrait
{
    public function testAnIdentityGrantedTheSubtreeDeleteControlRemovesTheSubtree(): void
    {
        $this->seedPruner();
        $this->seedTreeToPrune('prunable');

        $this->authenticatePruner();
        $this->ldapClient()->send(
            Operations::delete(LdapBackendStorageCommand::PRUNABLE_CONTAINER_DN),
            Controls::subtreeDelete(),
        );

        $this->authenticateUser();
        foreach ([
            LdapBackendStorageCommand::PRUNABLE_CONTAINER_DN,
            LdapBackendStorageCommand::PRUNE_GUARDED_DN,
            'ou=team,ou=prunable,dc=foo,dc=bar',
            'cn=deep,ou=team,ou=prunable,dc=foo,dc=bar',
        ] as $dn) {
            self::assertNull($this->ldapClient()->read($dn));
        }

        $this->asAdmin(fn(LdapClient $admin) => $admin->delete(LdapBackendStorageCommand::PRUNER_DN));
    }

    public function testTheSubtreeDeleteGrantReachesAnEntryItsHolderCannotDeleteDirectly(): void
    {
        $this->seedPruner();
        $this->seedTreeToPrune('prunable');

        $this->authenticatePruner();

        try {
            $this->ldapClient()->delete(LdapBackendStorageCommand::PRUNE_GUARDED_DN);
            self::fail('Deleting the guarded entry directly should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        $this->ldapClient()->send(
            Operations::delete(LdapBackendStorageCommand::PRUNABLE_CONTAINER_DN),
            Controls::subtreeDelete(),
        );

        $this->authenticateUser();
        self::assertNull($this->ldapClient()->read(LdapBackendStorageCommand::PRUNE_GUARDED_DN));

        $this->asAdmin(fn(LdapClient $admin) => $admin->delete(LdapBackendStorageCommand::PRUNER_DN));
    }

    public function testASubtreeDeleteIsRefusedWhereTheControlIsNotGranted(): void
    {
        $this->seedPruner();
        $this->seedTreeToPrune('unprunable');

        $this->authenticatePruner();

        try {
            $this->ldapClient()->send(
                Operations::delete('ou=unprunable,dc=foo,dc=bar'),
                Controls::subtreeDelete(),
            );
            self::fail('A subtree delete outside the granted container should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        $this->authenticateUser();
        self::assertNotNull($this->ldapClient()->read('cn=deep,ou=team,ou=unprunable,dc=foo,dc=bar'));

        $this->asAdmin(function (LdapClient $admin): void {
            $admin->send(
                Operations::delete('ou=unprunable,dc=foo,dc=bar'),
                Controls::subtreeDelete(),
            );
            $admin->delete(LdapBackendStorageCommand::PRUNER_DN);
        });
    }

    /**
     * Created per test rather than seeded, so the shared fixture's entry counts stay as every other case expects.
     */
    private function seedPruner(): void
    {
        $this->asAdmin(fn(LdapClient $admin) => $admin->create(Entry::fromArray(
            LdapBackendStorageCommand::PRUNER_DN,
            [
                'cn' => 'pruner',
                'sn' => 'Pruner',
                'userPassword' => LdapBackendStorageCommand::PRUNER_PASSWORD,
                'objectClass' => 'inetOrgPerson',
            ],
        )));
    }

    private function authenticatePruner(): void
    {
        $this->ldapClient()->bind(
            LdapBackendStorageCommand::PRUNER_DN,
            LdapBackendStorageCommand::PRUNER_PASSWORD,
        );
    }

    /**
     * A three-level tree under dc=foo,dc=bar whose cn=guarded leaf sits directly beneath the base.
     */
    private function seedTreeToPrune(string $ou): void
    {
        $base = "ou={$ou},dc=foo,dc=bar";

        $this->asAdmin(function (LdapClient $admin) use ($base, $ou): void {
            $admin->create(Entry::fromArray(
                $base,
                ['ou' => $ou, 'objectClass' => 'organizationalUnit'],
            ));
            $admin->create(Entry::fromArray(
                "cn=guarded,{$base}",
                ['cn' => 'guarded', 'sn' => 'Guarded', 'objectClass' => 'inetOrgPerson'],
            ));
            $admin->create(Entry::fromArray(
                "ou=team,{$base}",
                ['ou' => 'team', 'objectClass' => 'organizationalUnit'],
            ));
            $admin->create(Entry::fromArray(
                "cn=deep,ou=team,{$base}",
                ['cn' => 'deep', 'sn' => 'Deep', 'objectClass' => 'inetOrgPerson'],
            ));
        });
    }
}
