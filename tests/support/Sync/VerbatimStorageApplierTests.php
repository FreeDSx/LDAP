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

namespace Tests\Support\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\UnresolvedReplicaMovesException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkTarget;
use FreeDSx\Ldap\Server\Utility\Uuid;
use FreeDSx\Ldap\Sync\Consumer\ChangeApplierInterface;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Session;

/**
 * Shared behaviour of the verbatim applier, held to the same results on every storage it runs on.
 *
 * @mixin \PHPUnit\Framework\TestCase
 */
trait VerbatimStorageApplierTests
{
    private const UUID_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

    private const UUID_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

    private const UUID_C = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

    private const UUID_D = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';

    private ReadEntryInterface $reader;

    private WriteEntryInterface $writer;

    private ChangeApplierInterface $subject;

    public function test_an_add_stores_the_entry(): void
    {
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=alice,dc=example,dc=com'),
            ),
            $this->refreshSession(),
        );

        self::assertTrue($this->exists('cn=alice,dc=example,dc=com'));
    }

    public function test_a_modify_replaces_the_stored_entry(): void
    {
        $session = $this->refreshSession();

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                new Entry(
                    'cn=bob,dc=example,dc=com',
                    new Attribute('cn', 'bob'),
                    new Attribute('sn', 'Old'),
                ),
            ),
            $session,
        );
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_MODIFY,
                new Entry(
                    'cn=bob,dc=example,dc=com',
                    new Attribute('cn', 'bob'),
                    new Attribute('sn', 'New'),
                ),
            ),
            $session,
        );

        self::assertSame(
            'New',
            $this->value('cn=bob,dc=example,dc=com', 'sn'),
        );
    }

    public function test_a_delete_removes_the_entry(): void
    {
        $this->writer->store($this->entry('cn=carol,dc=example,dc=com'));

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_DELETE,
                $this->entry('cn=carol,dc=example,dc=com'),
            ),
            $this->refreshSession(),
        );

        self::assertFalse($this->exists('cn=carol,dc=example,dc=com'));
    }

    public function test_a_delete_removes_the_entry_holding_its_uuid_whatever_dn_it_names(): void
    {
        $this->writer->store($this->entry('cn=moved,dc=example,dc=com', self::UUID_B));

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_DELETE,
                $this->entry('cn=old,dc=example,dc=com', self::UUID_B),
            ),
            $this->persistSession(),
        );

        self::assertFalse($this->exists('cn=moved,dc=example,dc=com'));
    }

    public function test_a_delete_whose_uuid_the_replica_does_not_hold_leaves_the_entry_at_its_dn(): void
    {
        $this->writer->store($this->entry('cn=carol,dc=example,dc=com', self::UUID_A));

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_DELETE,
                $this->entry('cn=carol,dc=example,dc=com', self::UUID_B),
            ),
            $this->persistSession(),
        );

        self::assertTrue($this->exists('cn=carol,dc=example,dc=com'));
    }

    public function test_an_add_at_a_dn_held_by_another_entry_moves_that_entry_aside(): void
    {
        $this->writer->store($this->entry('cn=carol,dc=example,dc=com', self::UUID_A));

        $this->applyAdd('cn=carol,dc=example,dc=com', self::UUID_B);

        self::assertSame(
            self::UUID_B,
            $this->value('cn=carol,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            self::UUID_A,
            $this->value($this->slot(self::UUID_A), 'entryUUID'),
        );
    }

    public function test_a_readd_announced_before_the_delete_of_its_predecessor_is_kept(): void
    {
        $this->writer->store($this->entry('cn=carol,dc=example,dc=com', self::UUID_A));
        $session = $this->persistSession();

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=carol,dc=example,dc=com', self::UUID_B),
            ),
            $session,
        );
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_DELETE,
                $this->entry('cn=carol,dc=example,dc=com', self::UUID_A),
            ),
            $session,
        );

        self::assertSame(
            self::UUID_B,
            $this->value('cn=carol,dc=example,dc=com', 'entryUUID'),
        );
        self::assertFalse($this->exists($this->slot(self::UUID_A)));
    }

    public function test_reconcile_removes_locals_absent_from_the_present_phase(): void
    {
        foreach (['a' => self::UUID_A, 'b' => self::UUID_B, 'c' => self::UUID_C] as $cn => $uuid) {
            $this->writer->store($this->entry("cn=$cn,dc=example,dc=com", $uuid));
        }

        $session = $this->refreshSession();
        $this->subject->beginRefresh();
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=a,dc=example,dc=com', self::UUID_A),
            ),
            $session,
        );
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=b,dc=example,dc=com', self::UUID_B),
            ),
            $session,
        );
        $this->subject->reconcile();

        self::assertTrue($this->exists('cn=a,dc=example,dc=com'));
        self::assertTrue($this->exists('cn=b,dc=example,dc=com'));
        self::assertFalse($this->exists('cn=c,dc=example,dc=com'));
    }

    public function test_reconcile_removes_the_old_dn_of_an_entry_presented_elsewhere(): void
    {
        $this->writer->store($this->entry('cn=old,dc=example,dc=com'));

        $session = $this->refreshSession();
        $this->subject->beginRefresh();
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=new,dc=example,dc=com'),
            ),
            $session,
        );
        $this->subject->reconcile();

        self::assertFalse($this->exists('cn=old,dc=example,dc=com'));
        self::assertTrue($this->exists('cn=new,dc=example,dc=com'));
    }

    public function test_a_move_during_persist_relocates_rather_than_duplicating(): void
    {
        $this->writer->store($this->entry('cn=old,dc=example,dc=com'));

        $this->applyMove('cn=new,dc=example,dc=com', self::UUID_A);

        self::assertFalse(
            $this->exists('cn=old,dc=example,dc=com'),
            'The entry must not be left behind at the DN it moved from.',
        );
        self::assertTrue($this->exists('cn=new,dc=example,dc=com'));
    }

    public function test_a_moved_entry_takes_its_descendants_when_only_its_own_message_arrives(): void
    {
        $this->writer->store($this->entry('ou=staff,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=grace,ou=staff,dc=example,dc=com', self::UUID_B));

        $this->applyMove('ou=crew,dc=example,dc=com', self::UUID_A);

        self::assertFalse($this->exists('cn=grace,ou=staff,dc=example,dc=com'));
        self::assertSame(
            self::UUID_B,
            $this->value('cn=grace,ou=crew,dc=example,dc=com', 'entryUUID'),
        );
    }

    public function test_a_moved_entry_takes_an_entry_whose_parent_is_not_stored(): void
    {
        $this->writer->store($this->entry(
            'ou=staff,dc=example,dc=com',
            self::UUID_A,
        ));
        $this->writer->store($this->entry(
            'cn=g,ou=gone,ou=staff,dc=example,dc=com',
            self::UUID_C,
        ));

        $this->applyMove(
            'ou=crew,dc=example,dc=com',
            self::UUID_A,
        );

        self::assertFalse($this->exists('cn=g,ou=gone,ou=staff,dc=example,dc=com'));
        self::assertSame(
            self::UUID_C,
            $this->value(
                'cn=g,ou=gone,ou=crew,dc=example,dc=com',
                'entryUUID',
            ),
        );
    }

    public function test_an_entry_moved_aside_takes_an_entry_whose_parent_is_not_stored(): void
    {
        $this->writer->store($this->entry(
            'cn=a,dc=example,dc=com',
            self::UUID_A,
        ));
        $this->writer->store($this->entry(
            'cn=b,dc=example,dc=com',
            self::UUID_B,
        ));
        $this->writer->store($this->entry(
            'cn=o,ou=gone,cn=b,dc=example,dc=com',
            self::UUID_C,
        ));

        $this->applyMove(
            'cn=b,dc=example,dc=com',
            self::UUID_A,
        );
        $this->applyMove(
            'cn=c,dc=example,dc=com',
            self::UUID_B,
        );

        self::assertFalse($this->exists('cn=o,ou=gone,cn=b,dc=example,dc=com'));
        self::assertSame(
            self::UUID_C,
            $this->value(
                'cn=o,ou=gone,cn=c,dc=example,dc=com',
                'entryUUID',
            ),
        );
    }

    public function test_a_move_onto_a_dn_held_by_an_entry_moving_away_is_placed_at_once(): void
    {
        $this->writer->store($this->entry('cn=a,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=b,dc=example,dc=com', self::UUID_B));
        $this->writer->store($this->entry('cn=kid,cn=b,dc=example,dc=com', self::UUID_C));

        $this->applyMove('cn=b,dc=example,dc=com', self::UUID_A);
        $this->applyMove('cn=c,dc=example,dc=com', self::UUID_B);

        self::assertSame(
            self::UUID_A,
            $this->value('cn=b,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            self::UUID_C,
            $this->value('cn=kid,cn=c,dc=example,dc=com', 'entryUUID'),
        );
        self::assertFalse($this->exists('cn=a,dc=example,dc=com'));
        self::assertFalse($this->exists($this->slot(self::UUID_B)));
    }

    public function test_two_entries_trading_dns_are_both_placed_with_their_descendants(): void
    {
        $this->writer->store($this->entry('cn=a,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=kid,cn=a,dc=example,dc=com', self::UUID_C));
        $this->writer->store($this->entry('cn=b,dc=example,dc=com', self::UUID_B));
        $this->writer->store($this->entry('cn=pup,cn=b,dc=example,dc=com', self::UUID_D));

        $this->applyMove('cn=b,dc=example,dc=com', self::UUID_A);
        $this->applyMove('cn=a,dc=example,dc=com', self::UUID_B);

        self::assertSame(
            self::UUID_A,
            $this->value('cn=b,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            self::UUID_B,
            $this->value('cn=a,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            self::UUID_C,
            $this->value('cn=kid,cn=b,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            self::UUID_D,
            $this->value('cn=pup,cn=a,dc=example,dc=com', 'entryUUID'),
        );
    }

    public function test_an_entry_moved_under_the_dn_it_holds_takes_its_descendants_and_frees_that_dn(): void
    {
        $this->writer->store($this->entry('ou=a,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=kid,ou=a,dc=example,dc=com', self::UUID_C));

        $this->applyMove('ou=sub,ou=a,dc=example,dc=com', self::UUID_A);
        $this->applyAdd('ou=a,dc=example,dc=com', self::UUID_B);

        self::assertSame(
            self::UUID_A,
            $this->value('ou=sub,ou=a,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            self::UUID_C,
            $this->value('cn=kid,ou=sub,ou=a,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            self::UUID_B,
            $this->value('ou=a,dc=example,dc=com', 'entryUUID'),
        );
    }

    public function test_a_move_whose_descendant_lands_on_another_entry_moves_that_entry_aside(): void
    {
        $this->writer->store($this->entry('ou=a,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=kid,ou=a,dc=example,dc=com', self::UUID_C));
        $this->writer->store($this->entry('cn=kid,ou=b,dc=example,dc=com', self::UUID_D));

        $this->applyMove('ou=b,dc=example,dc=com', self::UUID_A);

        self::assertSame(
            self::UUID_A,
            $this->value('ou=b,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            self::UUID_C,
            $this->value('cn=kid,ou=b,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            self::UUID_D,
            $this->value('entryUUID=' . self::UUID_D . ',ou=b,dc=example,dc=com', 'entryUUID'),
        );
    }

    public function test_a_move_whose_grandchild_lands_on_another_entry_moves_that_entry_aside(): void
    {
        $grandchild = $this->uuidFor('grandchild');
        $this->writer->store($this->entry('ou=a,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('ou=kid,ou=a,dc=example,dc=com', self::UUID_C));
        $this->writer->store($this->entry('cn=g,ou=kid,ou=a,dc=example,dc=com', $grandchild));
        $this->writer->store($this->entry('cn=g,ou=kid,ou=b,dc=example,dc=com', self::UUID_D));

        $this->applyMove('ou=b,dc=example,dc=com', self::UUID_A);

        self::assertSame(
            self::UUID_C,
            $this->value('ou=kid,ou=b,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            $grandchild,
            $this->value('cn=g,ou=kid,ou=b,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            self::UUID_D,
            $this->value('entryUUID=' . self::UUID_D . ',ou=kid,ou=b,dc=example,dc=com', 'entryUUID'),
        );
    }

    public function test_a_move_carrying_an_entry_whose_parent_is_not_stored_onto_a_taken_dn_moves_that_entry_aside(): void
    {
        $this->writer->store($this->entry('ou=a,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=o,ou=gone,ou=a,dc=example,dc=com', self::UUID_C));
        $this->writer->store($this->entry('cn=o,ou=gone,ou=b,dc=example,dc=com', self::UUID_D));

        $this->applyMove('ou=b,dc=example,dc=com', self::UUID_A);

        self::assertSame(
            self::UUID_A,
            $this->value('ou=b,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            self::UUID_C,
            $this->value(
                'cn=o,ou=gone,ou=b,dc=example,dc=com',
                'entryUUID',
            ),
        );
        self::assertSame(
            self::UUID_D,
            $this->value(
                'entryUUID=' . self::UUID_D . ',ou=gone,ou=b,dc=example,dc=com',
                'entryUUID',
            ),
        );
    }

    public function test_an_entry_moved_aside_and_placed_by_its_change_in_the_next_window_is_not_reported(): void
    {
        $this->writer->store($this->entry('cn=a,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=b,dc=example,dc=com', self::UUID_B));

        $this->applyMove('cn=b,dc=example,dc=com', self::UUID_A);
        $this->subject->settle();
        $this->applyMove('cn=c,dc=example,dc=com', self::UUID_B);
        $this->subject->settle();
        $this->subject->settle();

        self::assertSame(
            self::UUID_B,
            $this->value('cn=c,dc=example,dc=com', 'entryUUID'),
        );
    }

    public function test_an_entry_moved_aside_and_then_deleted_is_not_reported(): void
    {
        $this->writer->store($this->entry('cn=a,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=b,dc=example,dc=com', self::UUID_B));

        $this->applyMove('cn=b,dc=example,dc=com', self::UUID_A);
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_DELETE,
                $this->entry('cn=b,dc=example,dc=com', self::UUID_B),
            ),
            $this->persistSession(),
        );
        $this->subject->settle();
        $this->subject->settle();

        self::assertFalse($this->exists($this->slot(self::UUID_B)));
    }

    public function test_an_entry_moved_aside_and_then_removed_by_reconcile_is_not_reported(): void
    {
        $this->writer->store($this->entry('cn=a,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=b,dc=example,dc=com', self::UUID_B));

        $this->subject->beginRefresh();
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=b,dc=example,dc=com', self::UUID_A),
            ),
            $this->refreshSession(),
        );
        $this->subject->reconcile();
        $this->subject->settle();
        $this->subject->settle();

        self::assertFalse($this->exists($this->slot(self::UUID_B)));
    }

    public function test_an_entry_moved_aside_that_no_change_places_is_reported_at_the_second_settle_and_kept(): void
    {
        $this->writer->store($this->entry('cn=a,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=b,dc=example,dc=com', self::UUID_B));

        $this->applyMove('cn=b,dc=example,dc=com', self::UUID_A);
        $this->subject->settle();

        try {
            $this->subject->settle();
            self::fail('The entry left aside should have been reported.');
        } catch (UnresolvedReplicaMovesException $e) {
            self::assertSame(
                ['cn=b,dc=example,dc=com'],
                $e->dns,
            );
        }

        self::assertSame(
            self::UUID_A,
            $this->value('cn=b,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            self::UUID_B,
            $this->value($this->slot(self::UUID_B), 'entryUUID'),
        );
    }

    public function test_a_parking_dn_held_by_malformed_data_is_reported_and_places_nothing(): void
    {
        $this->writer->store($this->entry('cn=a,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=b,dc=example,dc=com', self::UUID_B));
        $this->writer->store($this->entry($this->slot(self::UUID_B), self::UUID_C));

        try {
            $this->applyMove('cn=b,dc=example,dc=com', self::UUID_A);
            self::fail('The taken parking DN should have been reported.');
        } catch (UnresolvedReplicaMovesException $e) {
            self::assertSame(
                ['cn=b,dc=example,dc=com'],
                $e->dns,
            );
        }
        $this->subject->settle();
        $this->subject->settle();

        self::assertSame(
            self::UUID_A,
            $this->value('cn=a,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            self::UUID_B,
            $this->value('cn=b,dc=example,dc=com', 'entryUUID'),
        );
    }

    public function test_a_full_refresh_moves_back_an_entry_its_stale_parent_carried_away(): void
    {
        $this->writer->store($this->entry('ou=a,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('ou=b,dc=example,dc=com', self::UUID_D));
        $this->writer->store($this->entry('cn=kid,ou=b,dc=example,dc=com', self::UUID_C));

        $this->fullRefresh([
            self::UUID_C => 'cn=kid,ou=a,dc=example,dc=com',
            self::UUID_A => 'ou=old,dc=example,dc=com',
            self::UUID_B => 'ou=a,dc=example,dc=com',
            self::UUID_D => 'ou=b,dc=example,dc=com',
        ]);

        self::assertSame(
            self::UUID_C,
            $this->value('cn=kid,ou=a,dc=example,dc=com', 'entryUUID'),
        );
        self::assertFalse($this->exists('cn=kid,ou=old,dc=example,dc=com'));
    }

    public function test_a_full_refresh_moves_back_an_entry_carried_aside_with_the_stale_entry_it_was_placed_under(): void
    {
        $this->writer->store($this->entry('ou=a,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('ou=b,dc=example,dc=com', self::UUID_D));
        $this->writer->store($this->entry('cn=kid,ou=b,dc=example,dc=com', self::UUID_C));

        $this->fullRefresh([
            self::UUID_C => 'cn=kid,ou=a,dc=example,dc=com',
            self::UUID_B => 'ou=a,dc=example,dc=com',
            self::UUID_D => 'ou=b,dc=example,dc=com',
        ]);
        $this->subject->settle();
        $this->subject->settle();

        self::assertSame(
            self::UUID_C,
            $this->value('cn=kid,ou=a,dc=example,dc=com', 'entryUUID'),
        );
        self::assertFalse($this->exists($this->slot(self::UUID_A)));
        self::assertFalse($this->exists('cn=kid,' . $this->slot(self::UUID_A)));
    }

    public function test_a_full_refresh_moves_back_a_carried_parent_with_its_children(): void
    {
        $member = $this->uuidFor('member');
        $this->writer->store($this->entry('ou=a,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('ou=b,dc=example,dc=com', self::UUID_D));
        $this->writer->store($this->entry('ou=team,ou=b,dc=example,dc=com', self::UUID_C));
        $this->writer->store($this->entry('cn=m,ou=team,ou=b,dc=example,dc=com', $member));

        $this->fullRefresh([
            self::UUID_C => 'ou=team,ou=a,dc=example,dc=com',
            $member => 'cn=m,ou=team,ou=a,dc=example,dc=com',
            self::UUID_A => 'ou=old,dc=example,dc=com',
            self::UUID_B => 'ou=a,dc=example,dc=com',
            self::UUID_D => 'ou=b,dc=example,dc=com',
        ]);

        self::assertSame(
            self::UUID_C,
            $this->value('ou=team,ou=a,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            $member,
            $this->value('cn=m,ou=team,ou=a,dc=example,dc=com', 'entryUUID'),
        );
        self::assertFalse($this->exists('ou=team,ou=old,dc=example,dc=com'));
    }

    public function test_a_full_refresh_leaves_a_dn_to_the_entry_announced_there_after_the_one_it_moved_aside(): void
    {
        $this->writer->store($this->entry('cn=a,dc=example,dc=com', self::UUID_A));

        $this->fullRefresh([
            self::UUID_A => 'cn=a,dc=example,dc=com',
            self::UUID_B => 'CN=A,dc=example,dc=com',
        ]);

        self::assertSame(
            self::UUID_B,
            $this->value('cn=a,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            self::UUID_A,
            $this->value($this->slot(self::UUID_A), 'entryUUID'),
        );
    }

    public function test_reconcile_moves_back_an_entry_onto_a_stale_entrys_dn_and_removes_the_stale_entry(): void
    {
        $this->writer->store($this->entry('cn=elsewhere,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=t,dc=example,dc=com', self::UUID_C));

        $this->subject->beginRefresh();
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_PRESENT,
                $this->entry('cn=t,dc=example,dc=com', self::UUID_A),
            ),
            $this->refreshSession(),
        );
        $this->subject->reconcile();

        self::assertSame(
            self::UUID_A,
            $this->value('cn=t,dc=example,dc=com', 'entryUUID'),
        );
        self::assertFalse($this->exists('cn=elsewhere,dc=example,dc=com'));
        self::assertFalse($this->exists($this->slot(self::UUID_C)));
    }

    public function test_reconcile_moves_back_an_entry_once_removing_stale_entries_frees_its_dn(): void
    {
        $this->writer->store($this->entry('cn=elsewhere,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=t,dc=example,dc=com', self::UUID_C));
        $this->writer->store($this->entry($this->slot(self::UUID_C), self::UUID_D));

        $this->subject->beginRefresh();
        $this->announcePresent(
            'cn=t,dc=example,dc=com',
            self::UUID_A,
        );
        $this->subject->reconcile();

        self::assertSame(
            self::UUID_A,
            $this->value('cn=t,dc=example,dc=com', 'entryUUID'),
        );
        self::assertFalse($this->exists('cn=elsewhere,dc=example,dc=com'));
        self::assertFalse($this->exists($this->slot(self::UUID_C)));
    }

    public function test_reconcile_reports_an_entry_it_cannot_move_back(): void
    {
        $this->writer->store($this->entry('cn=elsewhere,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=t,dc=example,dc=com', self::UUID_C));
        $this->writer->store($this->entry($this->slot(self::UUID_C), self::UUID_D));
        $this->writer->store($this->entry('cn=c,dc=example,dc=com', self::UUID_B));

        $this->subject->beginRefresh();
        $this->announcePresent(
            'cn=t,dc=example,dc=com',
            self::UUID_A,
        );
        $this->announcePresent(
            'cn=c,dc=example,dc=com',
            self::UUID_C,
        );
        $this->announcePresent(
            $this->slot(self::UUID_C),
            self::UUID_D,
        );
        $this->announcePresent(
            'cn=c,dc=example,dc=com',
            self::UUID_B,
        );

        try {
            $this->subject->reconcile();
            self::fail('The entry left away from where it was announced should have been reported.');
        } catch (UnresolvedReplicaMovesException $e) {
            self::assertSame(
                ['cn=t,dc=example,dc=com'],
                $e->dns,
            );
        }

        self::assertSame(
            self::UUID_A,
            $this->value('cn=elsewhere,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            self::UUID_C,
            $this->value('cn=t,dc=example,dc=com', 'entryUUID'),
        );
    }

    public function test_a_full_refresh_moves_back_an_entry_that_moving_another_back_carried_away(): void
    {
        $y = $this->uuidFor('y');
        $q = $this->uuidFor('q');
        $r = $this->uuidFor('r');
        $x = $this->uuidFor('x');
        $leaf = $this->uuidFor('leaf');
        $this->writer->store($this->entry('ou=y0,dc=example,dc=com', $y));
        $this->writer->store($this->entry('ou=q0,dc=example,dc=com', $q));
        $this->writer->store($this->entry('ou=q,dc=example,dc=com', $r));
        $this->writer->store($this->entry('ou=x,ou=q,dc=example,dc=com', $x));
        $this->writer->store($this->entry('cn=leaf,ou=x,ou=q,dc=example,dc=com', $leaf));

        $this->fullRefresh([
            $y => 'ou=x,ou=q,dc=example,dc=com',
            $q => 'ou=q,dc=example,dc=com',
            $x => 'ou=x,ou=r,dc=example,dc=com',
            $r => 'ou=r,dc=example,dc=com',
            $leaf => 'cn=leaf,ou=x,ou=r,dc=example,dc=com',
        ]);

        self::assertSame(
            $leaf,
            $this->value('cn=leaf,ou=x,ou=r,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            $x,
            $this->value('ou=x,ou=r,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            $y,
            $this->value('ou=x,ou=q,dc=example,dc=com', 'entryUUID'),
        );
    }

    public function test_an_entry_named_by_its_own_uuid_takes_part_in_a_swap(): void
    {
        $selfNamed = $this->slot(self::UUID_A);
        $this->writer->store($this->entry($selfNamed, self::UUID_A));
        $this->writer->store($this->entry('cn=b,dc=example,dc=com', self::UUID_B));

        $this->applyMove('cn=b,dc=example,dc=com', self::UUID_A);
        $this->applyMove($selfNamed, self::UUID_B);

        self::assertSame(
            self::UUID_A,
            $this->value('cn=b,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            self::UUID_B,
            $this->value($selfNamed, 'entryUUID'),
        );
    }

    public function test_a_modify_at_the_same_dn_replaces_in_place(): void
    {
        $this->writer->store($this->entry('cn=alice,dc=example,dc=com'));

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_MODIFY,
                new Entry(
                    'cn=alice,dc=example,dc=com',
                    new Attribute('cn', 'x'),
                    new Attribute('sn', 'Changed'),
                    new Attribute('entryUUID', self::UUID_A),
                ),
            ),
            $this->persistSession(),
        );

        self::assertTrue($this->exists('cn=alice,dc=example,dc=com'));
        self::assertSame(
            'Changed',
            $this->value('cn=alice,dc=example,dc=com', 'sn'),
        );
    }

    public function test_an_entry_whose_selection_dropped_the_uuid_is_still_correlatable(): void
    {
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                new Entry(
                    'cn=old,dc=example,dc=com',
                    new Attribute('cn', 'x'),
                ),
            ),
            $this->persistSession(),
        );

        $this->applyMove('cn=new,dc=example,dc=com', self::UUID_A);

        self::assertFalse($this->exists('cn=old,dc=example,dc=com'));
        self::assertTrue($this->exists('cn=new,dc=example,dc=com'));
    }

    public function test_a_delete_set_removes_every_entry_it_names_by_uuid(): void
    {
        $this->writer->store($this->entry('cn=a,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=b,dc=example,dc=com', self::UUID_B));
        $this->writer->store($this->entry('cn=c,dc=example,dc=com', self::UUID_C));

        $this->subject->applyIdSet(
            $this->idSet(
                [self::UUID_A, self::UUID_C],
                deleted: true,
            ),
            $this->persistSession(),
        );

        self::assertFalse($this->exists('cn=a,dc=example,dc=com'));
        self::assertTrue($this->exists('cn=b,dc=example,dc=com'));
        self::assertFalse($this->exists('cn=c,dc=example,dc=com'));
    }

    public function test_a_delete_set_naming_an_unheld_uuid_is_a_no_op(): void
    {
        $this->writer->store($this->entry('cn=a,dc=example,dc=com', self::UUID_A));

        $this->subject->applyIdSet(
            $this->idSet(
                [self::UUID_B],
                deleted: true,
            ),
            $this->persistSession(),
        );

        self::assertTrue($this->exists('cn=a,dc=example,dc=com'));
    }

    public function test_entries_named_by_a_present_set_survive_reconciliation(): void
    {
        $this->writer->store($this->entry('cn=a,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=b,dc=example,dc=com', self::UUID_B));

        $this->subject->beginRefresh();
        $this->subject->applyIdSet(
            $this->idSet([self::UUID_A]),
            $this->refreshSession(),
        );
        $this->subject->reconcile();

        self::assertTrue($this->exists('cn=a,dc=example,dc=com'));
        self::assertFalse($this->exists('cn=b,dc=example,dc=com'));
    }

    public function test_a_present_set_is_matched_regardless_of_uuid_case(): void
    {
        $this->writer->store($this->entry('cn=a,dc=example,dc=com', self::UUID_A));

        $this->subject->beginRefresh();
        $this->subject->applyIdSet(
            $this->idSet([strtoupper(self::UUID_A)]),
            $this->refreshSession(),
        );
        $this->subject->reconcile();

        self::assertTrue($this->exists('cn=a,dc=example,dc=com'));
    }

    public function test_begin_refresh_clears_a_previous_present_set_of_uuids(): void
    {
        $this->writer->store($this->entry('cn=a,dc=example,dc=com', self::UUID_A));

        $this->subject->beginRefresh();
        $this->subject->applyIdSet(
            $this->idSet([self::UUID_A]),
            $this->refreshSession(),
        );

        $this->subject->beginRefresh();
        $this->subject->reconcile();

        self::assertFalse($this->exists('cn=a,dc=example,dc=com'));
    }

    public function test_begin_refresh_clears_the_previous_present_set(): void
    {
        $session = $this->refreshSession();

        $this->subject->beginRefresh();
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=a,dc=example,dc=com'),
            ),
            $session,
        );

        $this->subject->beginRefresh();
        $this->subject->reconcile();

        self::assertFalse($this->exists('cn=a,dc=example,dc=com'));
    }

    public function test_a_full_refresh_links_a_group_to_the_new_entry_holding_its_members_dn(): void
    {
        $this->writer->store($this->entry('cn=bob,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->group(
            'cn=team,dc=example,dc=com',
            self::UUID_C,
            'cn=bob,dc=example,dc=com',
        ));

        $this->refresh(
            $this->group(
                'cn=team,dc=example,dc=com',
                self::UUID_C,
                'cn=bob,dc=example,dc=com',
            ),
            $this->entry('cn=bob,dc=example,dc=com', self::UUID_B),
        );

        self::assertSame(
            ['cn=bob,dc=example,dc=com'],
            $this->members('cn=team,dc=example,dc=com'),
        );
    }

    public function test_a_full_refresh_links_a_group_to_the_new_entry_at_a_dn_a_renamed_container_carried_a_stale_one_onto(): void
    {
        $this->writer->store($this->entry('ou=z,dc=example,dc=com', self::UUID_D));
        $this->writer->store($this->entry('cn=bob,ou=z,dc=example,dc=com', self::UUID_A));

        $this->refresh(
            $this->group(
                'cn=team,dc=example,dc=com',
                self::UUID_C,
                'cn=bob,ou=a,dc=example,dc=com',
            ),
            $this->entry('ou=a,dc=example,dc=com', self::UUID_D),
            $this->entry('cn=bob,ou=a,dc=example,dc=com', self::UUID_B),
        );

        self::assertSame(
            ['cn=bob,ou=a,dc=example,dc=com'],
            $this->members('cn=team,dc=example,dc=com'),
        );
    }

    public function test_a_full_refresh_drops_a_member_the_group_no_longer_lists(): void
    {
        $this->writer->store($this->entry('cn=alice,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->entry('cn=bob,dc=example,dc=com', self::UUID_B));
        $this->writer->store($this->group(
            'cn=team,dc=example,dc=com',
            self::UUID_C,
            'cn=alice,dc=example,dc=com',
        ));

        $this->refresh(
            $this->entry('cn=alice,dc=example,dc=com', self::UUID_A),
            $this->entry('cn=bob,dc=example,dc=com', self::UUID_B),
            $this->group(
                'cn=team,dc=example,dc=com',
                self::UUID_C,
                'cn=bob,dc=example,dc=com',
            ),
        );

        self::assertSame(
            ['cn=bob,dc=example,dc=com'],
            $this->members('cn=team,dc=example,dc=com'),
        );
    }

    public function test_a_full_refresh_drops_every_member_of_a_group_sent_without_any(): void
    {
        $this->writer->store($this->entry('cn=alice,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->group(
            'cn=team,dc=example,dc=com',
            self::UUID_C,
            'cn=alice,dc=example,dc=com',
        ));

        $this->refresh(
            $this->entry('cn=alice,dc=example,dc=com', self::UUID_A),
            $this->entry('cn=team,dc=example,dc=com', self::UUID_C),
        );

        self::assertSame(
            [],
            $this->members('cn=team,dc=example,dc=com'),
        );
    }

    public function test_a_full_refresh_drops_every_member_of_a_group_sent_with_an_empty_member_attribute(): void
    {
        $this->writer->store($this->entry('cn=alice,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->group(
            'cn=team,dc=example,dc=com',
            self::UUID_C,
            'cn=alice,dc=example,dc=com',
        ));

        $this->refresh(
            $this->entry('cn=alice,dc=example,dc=com', self::UUID_A),
            $this->group(
                'cn=team,dc=example,dc=com',
                self::UUID_C,
            ),
        );

        self::assertSame(
            [],
            $this->members('cn=team,dc=example,dc=com'),
        );
    }

    public function test_a_group_sent_with_members_and_then_without_any_in_one_refresh_ends_with_none(): void
    {
        $this->refresh(
            $this->entry('cn=alice,dc=example,dc=com', self::UUID_A),
            $this->group(
                'cn=team,dc=example,dc=com',
                self::UUID_C,
                'cn=alice,dc=example,dc=com',
            ),
            $this->entry('cn=team,dc=example,dc=com', self::UUID_C),
        );

        self::assertSame(
            [],
            $this->members('cn=team,dc=example,dc=com'),
        );
    }

    public function test_a_group_keeps_its_members_until_the_refresh_links_the_values_it_held_back(): void
    {
        $this->writer->store($this->entry('cn=alice,dc=example,dc=com', self::UUID_A));
        $this->writer->store($this->group(
            'cn=team,dc=example,dc=com',
            self::UUID_C,
            'cn=alice,dc=example,dc=com',
        ));

        $this->subject->beginRefresh();
        $this->applyAll(
            $this->refreshSession(),
            $this->entry('cn=alice,dc=example,dc=com', self::UUID_A),
            $this->group(
                'cn=team,dc=example,dc=com',
                self::UUID_C,
                'cn=alice,dc=example,dc=com',
            ),
        );

        self::assertSame(
            ['cn=alice,dc=example,dc=com'],
            $this->members('cn=team,dc=example,dc=com'),
        );
    }

    public function test_a_refresh_links_the_values_a_group_was_last_sent_with(): void
    {
        $this->refresh(
            $this->entry('cn=alice,dc=example,dc=com', self::UUID_A),
            $this->entry('cn=bob,dc=example,dc=com', self::UUID_B),
            $this->group(
                'cn=team,dc=example,dc=com',
                self::UUID_C,
                'cn=alice,dc=example,dc=com',
            ),
            $this->group(
                'cn=team,dc=example,dc=com',
                self::UUID_C,
                'cn=bob,dc=example,dc=com',
            ),
        );

        self::assertSame(
            ['cn=bob,dc=example,dc=com'],
            $this->members('cn=team,dc=example,dc=com'),
        );
    }

    public function test_a_refresh_cut_short_has_its_values_linked_at_the_end_of_the_next_one(): void
    {
        $this->subject->beginRefresh();
        $this->applyAll(
            $this->refreshSession(),
            $this->entry('cn=alice,dc=example,dc=com', self::UUID_A),
            $this->group(
                'cn=team,dc=example,dc=com',
                self::UUID_C,
                'cn=alice,dc=example,dc=com',
            ),
        );

        $this->subject->beginRefresh();
        $this->subject->completeRefresh();

        self::assertSame(
            ['cn=alice,dc=example,dc=com'],
            $this->members('cn=team,dc=example,dc=com'),
        );
    }

    public function test_an_entry_deleted_during_a_refresh_takes_the_values_held_back_for_it(): void
    {
        $session = $this->refreshSession();

        $this->subject->beginRefresh();
        $this->applyAll(
            $session,
            $this->entry('cn=alice,dc=example,dc=com', self::UUID_A),
            $this->group(
                'cn=team,dc=example,dc=com',
                self::UUID_C,
                'cn=alice,dc=example,dc=com',
            ),
        );
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_DELETE,
                $this->entry('cn=team,dc=example,dc=com', self::UUID_C),
            ),
            $session,
        );
        $this->subject->completeRefresh();
        $this->applyAll(
            $this->persistSession(),
            $this->entry('cn=carol,dc=example,dc=com', self::UUID_B),
        );
        $this->subject->beginRefresh();
        $this->subject->completeRefresh();

        self::assertSame(
            [],
            $this->members('cn=carol,dc=example,dc=com'),
        );
    }

    public function test_a_change_after_the_refresh_links_its_values_at_once(): void
    {
        $this->applyAll(
            $this->persistSession(),
            $this->entry('cn=alice,dc=example,dc=com', self::UUID_A),
            $this->group(
                'cn=team,dc=example,dc=com',
                self::UUID_C,
                'cn=alice,dc=example,dc=com',
            ),
        );

        self::assertSame(
            ['cn=alice,dc=example,dc=com'],
            $this->members('cn=team,dc=example,dc=com'),
        );
    }

    public function test_a_refresh_carrying_a_uid_longer_than_the_replica_keeps_is_refused(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->refresh(
            $this->entry(
                'cn=alice,dc=example,dc=com',
                self::UUID_A,
            ),
            new Entry(
                'cn=team,dc=example,dc=com',
                new Attribute(
                    'cn',
                    'x',
                ),
                new Attribute(
                    'uniqueMember',
                    "cn=alice,dc=example,dc=com#'" . str_repeat(
                        '1',
                        LinkTarget::MAX_UID_BITS + 1,
                    ) . "'B",
                ),
                new Attribute(
                    'entryUUID',
                    self::UUID_C,
                ),
            ),
        );
    }

    /**
     * A stable UUID per name, so a test can refer to the same entry before and after it moves.
     */
    private function uuidFor(string $name): string
    {
        return Uuid::fromBinary(md5(
            $name,
            true,
        ));
    }

    /**
     * The DN an entry under the test's base is moved aside to.
     */
    private function slot(string $uuid): string
    {
        return 'entryUUID=' . $uuid . ',dc=example,dc=com';
    }

    private function applyAdd(
        string $dn,
        string $uuid,
    ): void {
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry($dn, $uuid),
            ),
            $this->persistSession(),
        );
    }

    private function applyMove(
        string $dn,
        string $uuid,
    ): void {
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_MODIFY,
                $this->entry($dn, $uuid),
            ),
            $this->persistSession(),
        );
    }

    private function announcePresent(
        string $dn,
        string $uuid,
    ): void {
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_PRESENT,
                $this->entry(
                    $dn,
                    $uuid,
                ),
            ),
            $this->refreshSession(),
        );
    }

    /**
     * @param array<string, string> $announced the DN each UUID is announced at, in the order they arrive
     */
    private function fullRefresh(array $announced): void
    {
        $session = $this->refreshSession();
        $this->subject->beginRefresh();

        foreach ($announced as $uuid => $dn) {
            $this->subject->apply(
                $this->syncResult(
                    SyncStateControl::STATE_ADD,
                    $this->entry(
                        $dn,
                        $uuid,
                    ),
                ),
                $session,
            );
        }

        $this->subject->reconcile();
        $this->subject->completeRefresh();
    }

    /**
     * A full refresh sending the entries in the order given, reconciled and completed as the consumer does.
     */
    private function refresh(Entry ...$entries): void
    {
        $this->subject->beginRefresh();
        $this->applyAll(
            $this->refreshSession(),
            ...$entries,
        );
        $this->subject->reconcile();
        $this->subject->completeRefresh();
    }

    private function applyAll(
        Session $session,
        Entry ...$entries,
    ): void {
        foreach ($entries as $entry) {
            $this->subject->apply(
                $this->syncResult(
                    SyncStateControl::STATE_ADD,
                    $entry,
                ),
                $session,
            );
        }
    }

    private function group(
        string $dn,
        string $uuid,
        string ...$members,
    ): Entry {
        return new Entry(
            $dn,
            new Attribute('cn', 'x'),
            new Attribute('member', ...$members),
            new Attribute('entryUUID', $uuid),
        );
    }

    /**
     * @return list<string>
     */
    private function members(string $dn): array
    {
        $entry = $this->reader->find((new Dn($dn))->normalize());
        self::assertNotNull($entry);

        return array_values($entry->get('member')?->getValues() ?? []);
    }

    /**
     * @param ?string $uuid The entry's identity; two DNs sharing one are the same entry, moved.
     */
    private function entry(
        string $dn,
        ?string $uuid = null,
    ): Entry {
        return new Entry(
            $dn,
            new Attribute('cn', 'x'),
            new Attribute('entryUUID', $uuid ?? self::UUID_A),
        );
    }

    private function syncResult(
        int $state,
        Entry $entry,
    ): SyncEntryResult {
        $message = new LdapMessageResponse(
            1,
            new SearchResultEntry($entry),
            new SyncStateControl(
                $state,
                Uuid::toBinary($entry->get('entryUUID')?->firstValue() ?? self::UUID_A),
            ),
        );

        return new SyncEntryResult(new EntryResult($message));
    }

    /**
     * @param list<string> $uuids
     */
    private function idSet(
        array $uuids,
        bool $deleted = false,
    ): SyncIdSetResult {
        return new SyncIdSetResult(new LdapMessageResponse(
            1,
            new SyncIdSet(
                array_map(
                    Uuid::toBinary(...),
                    $uuids,
                ),
                $deleted,
            ),
        ));
    }

    private function refreshSession(): Session
    {
        return new Session(
            Session::MODE_LISTEN,
            null,
        );
    }

    /**
     * Past the refresh, where nothing sweeps a stale copy afterwards.
     */
    private function persistSession(): Session
    {
        return $this->refreshSession()
            ->markRefreshComplete();
    }

    private function exists(string $dn): bool
    {
        return $this->reader->find((new Dn($dn))->normalize()) !== null;
    }

    private function value(
        string $dn,
        string $attribute,
    ): ?string {
        $entry = $this->reader->find((new Dn($dn))->normalize());

        if ($entry === null) {
            return null;
        }

        $values = $entry->get($attribute)?->getValues() ?? [];

        return $values[0] ?? null;
    }
}
