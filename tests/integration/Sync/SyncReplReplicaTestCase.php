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

namespace Tests\Integration\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ReferralException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operations;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\LdapReplicaCommand;
use Tests\Support\FreeDSx\Ldap\TestWorker;
use Throwable;

/**
 * A read-only replica mirroring a locally spawned provider over RFC 4533.
 */
abstract class SyncReplReplicaTestCase extends ServerTestCase
{
    private const CARRIED_ENTRY_CHANGES = __DIR__ . '/../../resources/changes/replica-carried-entry.ldif';

    private const SHIFTED_UNITS_CHANGES = __DIR__ . '/../../resources/changes/replica-shifted-units.ldif';

    private const RECREATED_MEMBER_CHANGES = __DIR__ . '/../../resources/changes/replica-recreated-member.ldif';

    private const RECREATED_UNIQUE_MEMBER_CHANGES = __DIR__ . '/../../resources/changes/replica-recreated-unique-member.ldif';

    public function setUp(): void
    {
        $this->setServerMode('ldap-replica');

        parent::setUp();
    }

    public function test_seeded_entries_replicate_to_the_replica(): void
    {
        self::assertNotNull($this->waitForReplica('cn=alice,ou=people,dc=foo,dc=bar'));
    }

    /**
     * Full refresh must ship both populations, or it would disagree with the incremental path.
     */
    public function test_seeded_subentries_replicate_to_the_replica(): void
    {
        self::assertNotNull($this->waitForReplica('cn=sync-policy,ou=people,dc=foo,dc=bar'));
    }

    public function test_an_add_on_the_provider_propagates_to_the_replica(): void
    {
        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->create(Entry::fromArray(
                'cn=dave,ou=people,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'dave',
                    'sn' => 'Davis',
                ],
            ));
        });

        self::assertNotNull($this->waitForReplica('cn=dave,ou=people,dc=foo,dc=bar'));
    }

    public function test_a_delete_on_the_provider_propagates_to_the_replica(): void
    {
        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->create(Entry::fromArray(
                'cn=eve,ou=people,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'eve',
                    'sn' => 'Evans',
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica('cn=eve,ou=people,dc=foo,dc=bar'));

        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->delete('cn=eve,ou=people,dc=foo,dc=bar');
        });
        self::assertNull($this->waitForReplicaGone('cn=eve,ou=people,dc=foo,dc=bar'));
    }

    /**
     * Coalesced deletes name only UUIDs, so the replica has to resolve each one rather than read a DN off the message.
     */
    public function test_multiple_deletes_on_the_provider_propagate_as_a_uuid_set(): void
    {
        $dns = [
            'cn=ivan,ou=people,dc=foo,dc=bar',
            'cn=judy,ou=people,dc=foo,dc=bar',
            'cn=karl,ou=people,dc=foo,dc=bar',
        ];

        $this->writeToProvider(static function (LdapClient $provider) use ($dns): void {
            foreach ($dns as $dn) {
                $provider->create(Entry::fromArray(
                    $dn,
                    [
                        'objectClass' => 'inetOrgPerson',
                        'cn' => explode('=', explode(',', $dn)[0])[1],
                        'sn' => 'Doomed',
                    ],
                ));
            }
        });

        foreach ($dns as $dn) {
            self::assertNotNull($this->waitForReplica($dn));
        }

        $this->writeToProvider(static function (LdapClient $provider) use ($dns): void {
            foreach ($dns as $dn) {
                $provider->delete($dn);
            }
        });

        foreach ($dns as $dn) {
            self::assertNull(
                $this->waitForReplicaGone($dn),
                'Every entry named by the delete set must be removed from the replica.',
            );
        }
    }

    /**
     * RFC 4533 §3.6 keys entries by entryUUID, so a move must relocate the replica's copy rather than add a second.
     */
    public function test_a_rename_on_the_provider_relocates_rather_than_duplicating(): void
    {
        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->create(Entry::fromArray(
                'cn=frank,ou=people,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'frank',
                    'sn' => 'Franklin',
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica('cn=frank,ou=people,dc=foo,dc=bar'));

        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->rename(
                'cn=frank,ou=people,dc=foo,dc=bar',
                'cn=franklin',
            );
        });

        self::assertNotNull($this->waitForReplica('cn=franklin,ou=people,dc=foo,dc=bar'));
        self::assertNull(
            $this->waitForReplicaGone('cn=frank,ou=people,dc=foo,dc=bar'),
            'The replica must not keep the entry at the DN it moved from.',
        );
    }

    /**
     * A subtree move journals one record per relocated entry, so every descendant has to relocate too.
     */
    public function test_a_subtree_move_on_the_provider_relocates_every_descendant(): void
    {
        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->create(Entry::fromArray(
                'ou=staff,dc=foo,dc=bar',
                [
                    'objectClass' => 'organizationalUnit',
                    'ou' => 'staff',
                ],
            ));
            $provider->create(Entry::fromArray(
                'cn=grace,ou=staff,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'grace',
                    'sn' => 'Hopper',
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica('cn=grace,ou=staff,dc=foo,dc=bar'));

        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->rename(
                'ou=staff,dc=foo,dc=bar',
                'ou=crew',
            );
        });

        self::assertNotNull($this->waitForReplica('cn=grace,ou=crew,dc=foo,dc=bar'));
        self::assertNull(
            $this->waitForReplicaGone('cn=grace,ou=staff,dc=foo,dc=bar'),
            'A descendant must not be left behind beneath the old base.',
        );
        self::assertNull(
            $this->waitForReplicaGone('ou=staff,dc=foo,dc=bar'),
            'The moved base must not be left behind either.',
        );
    }

    /**
     * RFC 4533 §4.1 wants a delete when a move takes an entry out of the content the consumer asked for.
     */
    public function test_a_move_out_of_the_replicated_scope_deletes_from_the_replica(): void
    {
        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->create(Entry::fromArray(
                'cn=heidi,ou=people,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'heidi',
                    'sn' => 'Lamarr',
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica('cn=heidi,ou=people,dc=foo,dc=bar'));

        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->move(
                'cn=heidi,ou=people,dc=foo,dc=bar',
                'dc=other,dc=test',
            );
        });

        self::assertNull(
            $this->waitForReplicaGone('cn=heidi,ou=people,dc=foo,dc=bar'),
            'An entry that left the replicated content must not linger on the replica.',
        );
    }

    public function test_an_entry_moved_where_the_sync_identity_cannot_read_leaves_the_replica(): void
    {
        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->create(Entry::fromArray(
                LdapReplicaCommand::HIDDEN_FROM_SYNC,
                [
                    'objectClass' => 'organizationalUnit',
                    'ou' => 'hidden',
                ],
            ));
            $provider->create(Entry::fromArray(
                'cn=ivy,ou=people,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'ivy',
                    'sn' => 'Ivy',
                    'userPassword' => 'ivypass',
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica('cn=ivy,ou=people,dc=foo,dc=bar'));
        $this->assertBind(
            'cn=ivy,ou=people,dc=foo,dc=bar',
            'ivypass',
            true,
        );

        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->move(
                'cn=ivy,ou=people,dc=foo,dc=bar',
                LdapReplicaCommand::HIDDEN_FROM_SYNC,
            );
        });

        self::assertNull($this->waitForReplicaGone('cn=ivy,ou=people,dc=foo,dc=bar'));
        $this->assertBind(
            'cn=ivy,ou=people,dc=foo,dc=bar',
            'ivypass',
            false,
        );
    }

    public function test_a_client_write_to_the_replica_is_referred_to_the_provider(): void
    {
        self::assertNotNull($this->waitForReplica('cn=alice,ou=people,dc=foo,dc=bar'));

        $client = $this->buildClient('tcp');
        $client->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        try {
            $this->expectException(ReferralException::class);
            $client->create(Entry::fromArray(
                'cn=nope,ou=people,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'nope',
                    'sn' => 'Nope',
                ],
            ));
        } finally {
            $client->unbind();
        }
    }

    /**
     * The URL is generated on one side and parsed on the other, so only a round trip proves either.
     */
    public function test_the_referral_url_survives_the_round_trip_to_the_client(): void
    {
        self::assertNotNull($this->waitForReplica('cn=alice,ou=people,dc=foo,dc=bar'));

        $client = $this->buildClient('tcp');
        $client->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        try {
            $client->create(Entry::fromArray(
                'cn=nope,ou=people,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'nope',
                    'sn' => 'Nope',
                ],
            ));

            self::fail('The write should have been referred to the provider.');
        } catch (ReferralException $e) {
            $referrals = $e->getReferrals();

            self::assertCount(
                1,
                $referrals,
            );
            self::assertSame(
                sprintf(
                    'ldap://127.0.0.1:%d/',
                    TestWorker::port(TestWorker::OFFSET_PROVIDER),
                ),
                $referrals[0]->toString(),
            );
            self::assertSame(
                '127.0.0.1',
                $referrals[0]->getHost(),
            );
            self::assertSame(
                TestWorker::port(TestWorker::OFFSET_PROVIDER),
                $referrals[0]->getPort(),
            );
            self::assertFalse($referrals[0]->getUseSsl());
        } finally {
            $client->unbind();
        }
    }

    public function test_a_password_modify_on_the_replica_is_referred_to_the_provider(): void
    {
        $target = 'cn=user,dc=foo,dc=bar';
        self::assertNotNull($this->waitForReplica($target));

        $client = $this->buildClient('tcp');
        $client->bind(
            $target,
            '12345',
        );

        try {
            $this->expectException(ReferralException::class);
            $client->sendAndReceive(Operations::passwordModify(
                $target,
                '12345',
                'localonly',
            ));
        } finally {
            $client->unbind();
        }
    }

    public function test_an_entry_deleted_and_readded_at_one_dn_in_one_window_replicates_as_the_new_entry(): void
    {
        $dn = 'cn=reused,ou=people,dc=foo,dc=bar';

        $this->writeToProvider(static function (LdapClient $provider) use ($dn): void {
            $provider->create(Entry::fromArray(
                $dn,
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'reused',
                    'sn' => 'Original',
                    'userPassword' => 'oldpass',
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica($dn));

        $this->writeToProvider(static function (LdapClient $provider) use ($dn): void {
            $provider->delete($dn);
            $provider->create(Entry::fromArray(
                $dn,
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'reused',
                    'sn' => 'Recreated',
                    'userPassword' => 'newpass',
                ],
            ));
        });
        $uuid = $this->providerUuidOf($dn);

        self::assertSame(
            $uuid,
            $this->waitForReplicaUuid(
                $dn,
                $uuid,
            ),
        );
        $this->assertBind(
            $dn,
            'newpass',
            true,
        );
    }

    public function test_an_entry_renamed_onto_a_dn_deleted_in_the_same_window_replicates_at_that_dn(): void
    {
        $target = 'cn=vacated,ou=people,dc=foo,dc=bar';
        $mover = 'cn=arriving,ou=people,dc=foo,dc=bar';

        $this->writeToProvider(static function (LdapClient $provider) use ($target, $mover): void {
            foreach ([$target, $mover] as $dn) {
                $provider->create(Entry::fromArray(
                    $dn,
                    [
                        'objectClass' => 'inetOrgPerson',
                        'cn' => explode('=', explode(',', $dn)[0])[1],
                        'sn' => 'Shuffled',
                    ],
                ));
            }
        });
        self::assertNotNull($this->waitForReplica($target));
        self::assertNotNull($this->waitForReplica($mover));
        $moverUuid = $this->providerUuidOf($mover);

        $this->writeToProvider(static function (LdapClient $provider) use ($target, $mover): void {
            $provider->delete($target);
            $provider->rename(
                $mover,
                'cn=vacated',
            );
        });

        self::assertSame(
            $moverUuid,
            $this->waitForReplicaUuid(
                $target,
                $moverUuid,
            ),
        );
        self::assertNull($this->waitForReplicaGone($mover));
    }

    public function test_repeated_failed_binds_lock_the_account_locally_on_the_replica(): void
    {
        $lockme = 'cn=lockme,ou=people,dc=foo,dc=bar';
        self::assertNotNull($this->waitForReplica($lockme));

        // The correct password works before any failures.
        $this->assertBind(
            $lockme,
            '12345',
            true,
        );

        // Two failed binds, each on a separate connection, reach pwdMaxFailure and lock locally.
        $this->assertBind(
            $lockme,
            'wrong',
            false,
        );
        $this->assertBind(
            $lockme,
            'wrong',
            false,
        );

        // The correct password is now rejected: the replica enforces its local lock across connections.
        $this->assertBind(
            $lockme,
            '12345',
            false,
        );
    }

    public function test_an_account_recreated_at_a_dn_starts_without_the_deleted_accounts_failures(): void
    {
        $dn = 'cn=recreated,ou=people,dc=foo,dc=bar';

        $this->writeToProvider(static function (LdapClient $provider) use ($dn): void {
            $provider->create(Entry::fromArray(
                $dn,
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'recreated',
                    'sn' => 'Original',
                    'userPassword' => 'oldpass',
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica($dn));
        $this->assertBind(
            $dn,
            'wrong',
            false,
        );

        $this->writeToProvider(static function (LdapClient $provider) use ($dn): void {
            $provider->delete($dn);
            $provider->create(Entry::fromArray(
                $dn,
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'recreated',
                    'sn' => 'Recreated',
                    'userPassword' => 'newpass',
                ],
            ));
        });
        $uuid = $this->providerUuidOf($dn);
        self::assertSame(
            $uuid,
            $this->waitForReplicaUuid(
                $dn,
                $uuid,
            ),
        );

        // One genuine failure stays below the threshold of two, unless the deleted account's failure carried over.
        $this->assertBind(
            $dn,
            'wrong',
            false,
        );
        $this->assertBind(
            $dn,
            'newpass',
            true,
        );
    }

    public function test_a_locally_locked_account_stays_locked_after_the_provider_renames_it(): void
    {
        $dn = 'cn=renamelock,ou=people,dc=foo,dc=bar';
        $renamed = 'cn=renamedlock,ou=people,dc=foo,dc=bar';

        $this->writeToProvider(static function (LdapClient $provider) use ($dn): void {
            $provider->create(Entry::fromArray(
                $dn,
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'renamelock',
                    'sn' => 'Locked',
                    'userPassword' => 'secret',
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica($dn));
        $this->assertBind(
            $dn,
            'wrong',
            false,
        );
        $this->assertBind(
            $dn,
            'wrong',
            false,
        );

        $this->writeToProvider(static function (LdapClient $provider) use ($dn): void {
            $provider->rename(
                $dn,
                'cn=renamedlock',
            );
        });
        self::assertNotNull($this->waitForReplica($renamed));

        $this->assertBind(
            $renamed,
            'secret',
            false,
        );
    }

    public function test_a_group_keeps_a_member_the_provider_renames(): void
    {
        $member = 'cn=teammate,ou=people,dc=foo,dc=bar';
        $renamed = 'cn=renamedmate,ou=people,dc=foo,dc=bar';
        $group = 'cn=team,ou=people,dc=foo,dc=bar';

        $this->writeToProvider(static function (LdapClient $provider) use ($member, $group): void {
            $provider->create(Entry::fromArray(
                $member,
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'teammate',
                    'sn' => 'Mate',
                ],
            ));
            $provider->create(Entry::fromArray(
                $group,
                [
                    'objectClass' => 'groupOfNames',
                    'cn' => 'team',
                    'member' => $member,
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica($group));

        $this->writeToProvider(static function (LdapClient $provider) use ($member): void {
            $provider->rename(
                $member,
                'cn=renamedmate',
            );
        });
        self::assertNotNull($this->waitForReplica($renamed));

        self::assertSame(
            [$renamed],
            array_values($this->tryReadFromReplica($group, ['member'])?->get('member')?->getValues() ?? []),
        );
    }

    public function test_a_group_keeps_a_member_renamed_away_while_a_new_entry_takes_its_dn(): void
    {
        $member = 'cn=claimed,ou=people,dc=foo,dc=bar';
        $renamed = 'cn=claimedaway,ou=people,dc=foo,dc=bar';
        $group = 'cn=claimteam,ou=people,dc=foo,dc=bar';

        $this->writeToProvider(static function (LdapClient $provider) use ($member, $group): void {
            $provider->create(Entry::fromArray(
                $member,
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'claimed',
                    'sn' => 'Original',
                ],
            ));
            $provider->create(Entry::fromArray(
                $group,
                [
                    'objectClass' => 'groupOfNames',
                    'cn' => 'claimteam',
                    'member' => $member,
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica($group));
        $memberUuid = $this->providerUuidOf($member);

        $this->writeToProvider(static function (LdapClient $provider) use ($member, $renamed): void {
            $provider->rename(
                $member,
                'cn=claimedaway',
            );
            $provider->create(Entry::fromArray(
                $member,
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'claimed',
                    'sn' => 'Newcomer',
                ],
            ));
            $provider->sendAndReceive(Operations::modify(
                $renamed,
                Change::replace(
                    'sn',
                    'Moved',
                ),
            ));
        });
        $newcomerUuid = $this->providerUuidOf($member);

        self::assertSame(
            $memberUuid,
            $this->waitForReplicaUuid(
                $renamed,
                $memberUuid,
            ),
        );
        self::assertSame(
            $newcomerUuid,
            $this->waitForReplicaUuid(
                $member,
                $newcomerUuid,
            ),
        );
        self::assertSame(
            [$renamed],
            array_values($this->tryReadFromReplica($group, ['member'])?->get('member')?->getValues() ?? []),
        );
    }

    public function test_a_full_refresh_moves_back_an_entry_its_stale_parent_carried_away(): void
    {
        $carried = 'cn=carried,ou=people,dc=foo,dc=bar';

        $this->writeToProvider(static function (LdapClient $provider) use ($carried): void {
            $provider->create(Entry::fromArray(
                $carried,
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'carried',
                    'sn' => 'Carried',
                ],
            ));
            $provider->create(Entry::fromArray(
                'ou=carrier,dc=foo,dc=bar',
                [
                    'objectClass' => 'organizationalUnit',
                    'ou' => 'carrier',
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica('ou=carrier,dc=foo,dc=bar'));
        $uuid = $this->providerUuidOf($carried);

        $this->restartAfterProviderChanges(self::CARRIED_ENTRY_CHANGES);

        self::assertSame(
            $uuid,
            $this->waitForReplicaUuid(
                'cn=carried,ou=carrier,dc=foo,dc=bar',
                $uuid,
            ),
        );
        self::assertNull($this->waitForReplicaGone('cn=carried,ou=carrier-old,dc=foo,dc=bar'));
    }

    public function test_a_full_refresh_moves_back_an_entry_that_moving_another_back_carried_away(): void
    {
        $this->writeToProvider(static function (LdapClient $provider): void {
            foreach (['shift-y', 'shift-q0', 'shift-x', 'shift-q'] as $unit) {
                $provider->create(Entry::fromArray(
                    'ou=' . $unit . ',dc=foo,dc=bar',
                    [
                        'objectClass' => 'organizationalUnit',
                        'ou' => $unit,
                    ],
                ));
            }
            $provider->create(Entry::fromArray(
                'cn=shift-leaf,ou=shift-x,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'shift-leaf',
                    'sn' => 'Leaf',
                ],
            ));
            $provider->move(
                'ou=shift-x,dc=foo,dc=bar',
                'ou=shift-q,dc=foo,dc=bar',
            );
        });
        $leaf = 'cn=shift-leaf,ou=shift-x,ou=shift-q,dc=foo,dc=bar';
        self::assertNotNull($this->waitForReplica($leaf));
        $uuid = $this->providerUuidOf($leaf);

        $this->restartAfterProviderChanges(self::SHIFTED_UNITS_CHANGES);

        self::assertSame(
            $uuid,
            $this->waitForReplicaUuid(
                'cn=shift-leaf,ou=shift-x,ou=shift-r,dc=foo,dc=bar',
                $uuid,
            ),
        );
    }

    public function test_a_full_refresh_links_a_group_to_the_entry_created_again_at_its_members_dn(): void
    {
        $member = 'cn=recreated,ou=people,dc=foo,dc=bar';
        $group = 'cn=reteam,ou=people,dc=foo,dc=bar';

        $this->writeToProvider(static function (LdapClient $provider) use ($member, $group): void {
            $provider->create(Entry::fromArray(
                $member,
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'recreated',
                    'sn' => 'Original',
                ],
            ));
            $provider->create(Entry::fromArray(
                $group,
                [
                    'objectClass' => 'groupOfNames',
                    'cn' => 'reteam',
                    'member' => $member,
                ],
            ));
        });
        self::assertSame(
            [$member],
            $this->waitForReplicaValues(
                $group,
                'member',
                [$member],
            ),
        );

        $this->restartAfterProviderChanges(self::RECREATED_MEMBER_CHANGES);
        $uuid = $this->providerUuidOf($member);

        self::assertSame(
            $uuid,
            $this->waitForReplicaUuid(
                $member,
                $uuid,
            ),
        );
        self::assertSame(
            [$member],
            $this->waitForReplicaValues(
                $group,
                'member',
                [$member],
            ),
        );
    }

    public function test_a_group_keeps_a_unique_member_and_its_uid_the_provider_renames(): void
    {
        $member = 'cn=uniquemate,ou=people,dc=foo,dc=bar';
        $renamed = 'cn=renameduniquemate,ou=people,dc=foo,dc=bar';
        $group = 'cn=uniqueteam,ou=people,dc=foo,dc=bar';

        $this->writeToProvider(static function (LdapClient $provider) use ($member, $group): void {
            $provider->create(Entry::fromArray(
                $member,
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'uniquemate',
                    'sn' => 'Mate',
                ],
            ));
            $provider->create(Entry::fromArray(
                $group,
                [
                    'objectClass' => 'groupOfUniqueNames',
                    'cn' => 'uniqueteam',
                    'uniqueMember' => $member . "#'0101'B",
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica($group));

        $this->writeToProvider(static function (LdapClient $provider) use ($member): void {
            $provider->rename(
                $member,
                'cn=renameduniquemate',
            );
        });
        self::assertNotNull($this->waitForReplica($renamed));

        self::assertSame(
            [$renamed . "#'0101'B"],
            array_values($this->tryReadFromReplica(
                $group,
                ['uniqueMember'],
            )?->get('uniqueMember')?->getValues() ?? []),
        );
    }

    public function test_a_full_refresh_links_a_unique_member_and_its_uid_to_the_entry_created_again_at_its_dn(): void
    {
        $member = 'cn=recreatedunique,ou=people,dc=foo,dc=bar';
        $group = 'cn=reuniqueteam,ou=people,dc=foo,dc=bar';

        $this->writeToProvider(static function (LdapClient $provider) use ($member, $group): void {
            $provider->create(Entry::fromArray(
                $member,
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'recreatedunique',
                    'sn' => 'Original',
                ],
            ));
            $provider->create(Entry::fromArray(
                $group,
                [
                    'objectClass' => 'groupOfUniqueNames',
                    'cn' => 'reuniqueteam',
                    'uniqueMember' => $member . "#'0101'B",
                ],
            ));
        });
        self::assertSame(
            [$member . "#'0101'B"],
            $this->waitForReplicaValues(
                $group,
                'uniqueMember',
                [$member . "#'0101'B"],
            ),
        );

        $this->restartAfterProviderChanges(self::RECREATED_UNIQUE_MEMBER_CHANGES);
        $uuid = $this->providerUuidOf($member);

        self::assertSame(
            $uuid,
            $this->waitForReplicaUuid(
                $member,
                $uuid,
            ),
        );
        self::assertSame(
            [$member . "#'0101'B"],
            $this->waitForReplicaValues(
                $group,
                'uniqueMember',
                [$member . "#'0101'B"],
            ),
        );
    }

    /**
     * Hook for subclasses to name the runner the replica and its provider run under.
     *
     * @return list<string>
     */
    protected static function runnerArgs(): array
    {
        return [];
    }

    /**
     * Restarts both servers on the databases they hold, with the provider replaying changes the replica missed.
     */
    private function restartAfterProviderChanges(string $changes): void
    {
        $this->createServerProcess(
            'tcp',
            [
                ...static::runnerArgs(),
                '--keep-replica-db',
                '--keep-provider-db',
                '--provider-changes=' . $changes,
            ],
        );
    }

    private function assertBind(
        string $dn,
        string $password,
        bool $shouldSucceed,
    ): void {
        $client = $this->buildClient('tcp');

        try {
            $client->bind(
                $dn,
                $password,
            );
            self::assertTrue(
                $shouldSucceed,
                "Expected the bind for {$dn} to fail.",
            );
        } catch (BindException $e) {
            self::assertFalse(
                $shouldSucceed,
                "Expected the bind for {$dn} to succeed: {$e->getMessage()}.",
            );
        } finally {
            try {
                $client->unbind();
            } catch (Throwable) {
                // The connection may already be gone after a failed bind.
            }
        }
    }

    private function waitForReplica(
        string $dn,
        float $timeoutSeconds = 15.0,
    ): ?Entry {
        $deadline = microtime(true) + $timeoutSeconds;

        do {
            $entry = $this->tryReadFromReplica($dn);

            if ($entry !== null) {
                return $entry;
            }

            usleep(100_000);
        } while (microtime(true) < $deadline);

        return null;
    }

    private function waitForReplicaGone(
        string $dn,
        float $timeoutSeconds = 15.0,
    ): ?Entry {
        $deadline = microtime(true) + $timeoutSeconds;

        do {
            $entry = $this->tryReadFromReplica($dn);

            if ($entry === null) {
                return null;
            }

            usleep(100_000);
        } while (microtime(true) < $deadline);

        return $entry;
    }

    private function waitForReplicaUuid(
        string $dn,
        string $uuid,
        float $timeoutSeconds = 15.0,
    ): ?string {
        $deadline = microtime(true) + $timeoutSeconds;

        do {
            $held = $this->tryReadFromReplica(
                $dn,
                ['entryUUID'],
            )?->get('entryUUID')?->firstValue();

            if ($held === $uuid) {
                return $held;
            }

            usleep(100_000);
        } while (microtime(true) < $deadline);

        return $held;
    }

    /**
     * @param list<string> $values
     *
     * @return list<string>
     */
    private function waitForReplicaValues(
        string $dn,
        string $attribute,
        array $values,
        float $timeoutSeconds = 15.0,
    ): array {
        $deadline = microtime(true) + $timeoutSeconds;

        do {
            $held = array_values($this->tryReadFromReplica(
                $dn,
                [$attribute],
            )?->get($attribute)?->getValues() ?? []);

            if ($held === $values) {
                return $held;
            }

            usleep(100_000);
        } while (microtime(true) < $deadline);

        return $held;
    }

    /**
     * @param list<string> $attributes
     */
    private function tryReadFromReplica(
        string $dn,
        array $attributes = [],
    ): ?Entry {
        try {
            $client = $this->buildClient('tcp');
            $client->bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            );
            $entry = $client->read(
                $dn,
                $attributes,
            );
            $client->unbind();

            return $entry;
        } catch (Throwable) {
            return null;
        }
    }

    private function providerUuidOf(string $dn): string
    {
        $uuid = null;

        $this->writeToProvider(static function (LdapClient $provider) use ($dn, &$uuid): void {
            $uuid = $provider->read(
                $dn,
                ['entryUUID'],
            )?->get('entryUUID')?->firstValue();
        });

        self::assertIsString($uuid);

        return $uuid;
    }

    /**
     * @param callable(LdapClient): void $write
     */
    private function writeToProvider(callable $write): void
    {
        $provider = $this->getClient(
            (new ClientOptions())
                ->setPort(TestWorker::port(TestWorker::OFFSET_PROVIDER))
                ->setServers(['127.0.0.1'])
                ->setSslValidateCert(false),
        );

        try {
            $provider->bind(
                'cn=admin,dc=foo,dc=bar',
                '12345',
            );
            $write($provider);
        } finally {
            $provider->unbind();
        }
    }
}
