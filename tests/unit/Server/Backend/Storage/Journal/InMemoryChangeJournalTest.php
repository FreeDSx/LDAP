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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Journal;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionPolicy;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;

final class InMemoryChangeJournalTest extends TestCase
{
    private InMemoryChangeJournal $subject;

    private FrozenClock $clock;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromString('2025-05-15T12:00:00');
        $this->subject = new InMemoryChangeJournal(
            new ReplicaId('node-a'),
            $this->clock,
        );
    }

    public function test_it_allocates_strictly_increasing_seq_numbers(): void
    {
        $first = $this->subject->append($this->change('cn=a,dc=example,dc=com'));
        $second = $this->subject->append($this->change('cn=b,dc=example,dc=com'));
        $third = $this->subject->append($this->change('cn=c,dc=example,dc=com'));

        self::assertSame(
            1,
            $first->seq,
        );
        self::assertSame(
            2,
            $second->seq,
        );
        self::assertSame(
            3,
            $third->seq,
        );
    }

    public function test_appending_several_changes_allocates_consecutive_seqs_after_the_last(): void
    {
        $this->subject->append($this->change('cn=a,dc=example,dc=com'));

        $records = $this->subject->appendAll([
            $this->change('cn=b,dc=example,dc=com'),
            $this->change('cn=c,dc=example,dc=com'),
        ]);

        self::assertSame(
            [2, 3],
            array_map(
                static fn(ChangeRecord $record): int => $record->seq,
                $records,
            ),
        );
    }

    public function test_latest_seq_is_zero_until_anything_is_appended(): void
    {
        self::assertSame(
            0,
            $this->subject->latestSeq(),
        );

        $this->subject->append($this->change('cn=a,dc=example,dc=com'));

        self::assertSame(
            1,
            $this->subject->latestSeq(),
        );
    }

    public function test_it_stamps_the_record_with_origin_clock_and_change(): void
    {
        $change = $this->change('cn=a,dc=example,dc=com');

        $record = $this->subject->append($change);

        self::assertSame(
            $change,
            $record->change,
        );
        self::assertTrue($record->origin->equals(new ReplicaId('node-a')));
        self::assertEquals(
            $this->clock->now(),
            $record->createdAt,
        );
    }

    public function test_read_returns_only_records_after_the_given_seq(): void
    {
        $this->subject->append($this->change('cn=a,dc=example,dc=com'));
        $this->subject->append($this->change('cn=b,dc=example,dc=com'));
        $this->subject->append($this->change('cn=c,dc=example,dc=com'));

        $seqs = array_map(
            static fn(ChangeRecord $record): int => $record->seq,
            iterator_to_array($this->subject->read(1)),
        );

        self::assertSame(
            [2, 3],
            $seqs,
        );
    }

    public function test_read_without_an_argument_returns_everything(): void
    {
        $this->subject->append($this->change('cn=a,dc=example,dc=com'));
        $this->subject->append($this->change('cn=b,dc=example,dc=com'));

        self::assertCount(
            2,
            iterator_to_array($this->subject->read()),
        );
    }

    public function test_an_unbounded_policy_prunes_nothing(): void
    {
        $this->subject->append($this->change('cn=a,dc=example,dc=com'));
        $this->subject->append($this->change('cn=b,dc=example,dc=com'));

        self::assertSame(
            0,
            $this->subject->prune(new RetentionPolicy()),
        );
        self::assertCount(
            2,
            iterator_to_array($this->subject->read()),
        );
    }

    public function test_the_record_cap_keeps_only_the_newest_records(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->subject->append($this->change("cn={$i},dc=example,dc=com"));
        }

        $removed = $this->subject->prune(new RetentionPolicy(maxRecords: 2));

        $seqs = array_map(
            static fn(ChangeRecord $record): int => $record->seq,
            iterator_to_array($this->subject->read()),
        );
        self::assertSame(
            3,
            $removed,
        );
        self::assertSame(
            [4, 5],
            $seqs,
        );
    }

    public function test_the_age_window_drops_records_older_than_the_horizon(): void
    {
        $this->subject->append($this->change('cn=old,dc=example,dc=com'));
        $this->clock->setTo($this->clock->now()->modify('+10 seconds'));
        $this->subject->append($this->change('cn=new,dc=example,dc=com'));

        $removed = $this->subject->prune(new RetentionPolicy(maxAgeSeconds: 5));

        $dns = array_map(
            static fn(ChangeRecord $record): string => $record->change->dn->toString(),
            iterator_to_array($this->subject->read()),
        );
        self::assertSame(
            1,
            $removed,
        );
        self::assertSame(
            ['cn=new,dc=example,dc=com'],
            $dns,
        );
    }

    public function test_pruning_leaves_the_seq_counter_climbing(): void
    {
        $this->subject->append($this->change('cn=a,dc=example,dc=com'));
        $this->subject->append($this->change('cn=b,dc=example,dc=com'));
        $this->subject->append($this->change('cn=c,dc=example,dc=com'));

        $this->subject->prune(new RetentionPolicy(maxRecords: 1));

        self::assertSame(
            3,
            $this->subject->latestSeq(),
        );
        self::assertSame(
            4,
            $this->subject->append($this->change('cn=d,dc=example,dc=com'))->seq,
        );
    }

    public function test_it_retains_from_any_seq_when_nothing_has_been_pruned(): void
    {
        $this->subject->append($this->change('cn=a,dc=example,dc=com'));
        $this->subject->append($this->change('cn=b,dc=example,dc=com'));

        self::assertTrue($this->subject->retainsSince(0));
        self::assertTrue($this->subject->retainsSince(1));
    }

    public function test_a_cookie_at_the_pruned_floor_is_still_retained(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->subject->append($this->change("cn={$i},dc=example,dc=com"));
        }
        $this->subject->prune(new RetentionPolicy(maxRecords: 2));

        // Pruned seq 1-3, retained 4-5: a consumer last at seq 3 still gets every record it needs.
        self::assertTrue($this->subject->retainsSince(3));
    }

    public function test_a_cookie_below_the_pruned_floor_has_lapsed(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->subject->append($this->change("cn={$i},dc=example,dc=com"));
        }
        $this->subject->prune(new RetentionPolicy(maxRecords: 2));

        // A consumer last at seq 2 needs seq 3, which was pruned.
        self::assertFalse($this->subject->retainsSince(2));
    }

    public function test_a_fully_pruned_journal_only_retains_a_caught_up_cookie(): void
    {
        $this->subject->append($this->change('cn=a,dc=example,dc=com'));
        $this->subject->append($this->change('cn=b,dc=example,dc=com'));
        $this->clock->setTo($this->clock->now()->modify('+10 seconds'));
        $this->subject->prune(new RetentionPolicy(maxAgeSeconds: 5));

        self::assertFalse($this->subject->retainsSince(1));
        self::assertTrue($this->subject->retainsSince(2));
    }

    private function change(string $dn): PendingChange
    {
        return new PendingChange(
            changeType: ChangeType::Add,
            dn: new Dn($dn),
            entryUuid: '11111111-1111-4111-8111-111111111111',
            authzId: AuthzId::anonymous(),
        );
    }
}
