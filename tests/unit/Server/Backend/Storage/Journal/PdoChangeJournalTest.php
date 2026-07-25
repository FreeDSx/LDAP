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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\PdoChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionPolicy;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Pdo\RecordingPdo;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;

final class PdoChangeJournalTest extends TestCase
{
    private const UUID = '11111111-1111-4111-8111-111111111111';

    private PdoChangeJournal $subject;

    private FrozenClock $clock;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromString('2025-05-15T12:00:00');
        $pdo = new PDO('sqlite::memory:');
        $dialect = new SqliteDialect();
        PdoStorage::initialize($pdo, $dialect);
        $provider = new SharedPdoConnectionProvider($pdo);

        $this->subject = new PdoChangeJournal(
            new PdoTransactor(
                $provider,
                $dialect,
            ),
            $dialect,
            new PdoStatementPool($provider),
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

    public function test_it_round_trips_a_delete_record_with_a_pre_image(): void
    {
        $preImage = Entry::fromArray(
            'cn=a,dc=example,dc=com',
            ['cn' => ['a'], 'sn' => ['Doe']],
        );
        $this->subject->append(new PendingChange(
            changeType: ChangeType::Delete,
            dn: new Dn('cn=a,dc=example,dc=com'),
            entryUuid: self::UUID,
            authzId: AuthzId::fromDn(new Dn('cn=admin,dc=example,dc=com')),
            preImage: $preImage,
        ));

        $records = iterator_to_array($this->subject->read());
        self::assertCount(
            1,
            $records,
        );
        $record = $records[0];

        self::assertSame(
            ChangeType::Delete,
            $record->change->changeType,
        );
        self::assertSame(
            'cn=a,dc=example,dc=com',
            $record->change->dn->toString(),
        );
        self::assertSame(
            self::UUID,
            $record->change->entryUuid,
        );
        self::assertSame(
            'dn:cn=admin,dc=example,dc=com',
            $record->change->authzId->toString(),
        );
        self::assertTrue($record->origin->equals(new ReplicaId('node-a')));
        self::assertEquals(
            $this->clock->now(),
            $record->createdAt,
        );
        self::assertNotNull($record->change->preImage);
        self::assertSame(
            ['cn' => ['a'], 'sn' => ['Doe']],
            $record->change->preImage->toArray(),
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

    public function test_the_seq_counter_survives_a_full_prune_and_keeps_climbing(): void
    {
        $this->subject->append($this->change('cn=a,dc=example,dc=com'));
        $this->subject->append($this->change('cn=b,dc=example,dc=com'));
        $this->subject->append($this->change('cn=c,dc=example,dc=com'));
        $this->clock->setTo($this->clock->now()->modify('+10 seconds'));

        // Age out every record: an empty table has no MAX(seq), so latestSeq() can only come from the counter.
        $removed = $this->subject->prune(new RetentionPolicy(maxAgeSeconds: 5));

        self::assertSame(
            3,
            $removed,
        );
        self::assertSame(
            3,
            $this->subject->latestSeq(),
        );
        self::assertSame(
            4,
            $this->subject->append($this->change('cn=d,dc=example,dc=com'))->seq,
        );
    }

    public function test_a_cookie_below_the_pruned_floor_has_lapsed(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->subject->append($this->change("cn={$i},dc=example,dc=com"));
        }
        $this->subject->prune(new RetentionPolicy(maxRecords: 2));

        self::assertTrue($this->subject->retainsSince(3));
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

    public function test_appending_within_an_open_transaction_does_not_nest_a_savepoint(): void
    {
        $pdo = new RecordingPdo('sqlite::memory:');
        $dialect = new SqliteDialect();
        PdoStorage::initialize($pdo, $dialect);
        $provider = new SharedPdoConnectionProvider($pdo);
        $transactor = new PdoTransactor(
            $provider,
            $dialect,
        );
        $journal = new PdoChangeJournal(
            $transactor,
            $dialect,
            new PdoStatementPool($provider),
            new ReplicaId('node-a'),
            $this->clock,
        );

        $transactor->atomic(static function () use ($journal): void {
            $journal->append(new PendingChange(
                changeType: ChangeType::Add,
                dn: new Dn('cn=a,dc=example,dc=com'),
                entryUuid: self::UUID,
                authzId: AuthzId::anonymous(),
            ));
        });

        self::assertSame(
            [],
            $pdo->executedMatching('SAVEPOINT'),
        );
        self::assertCount(
            1,
            iterator_to_array($journal->read()),
        );
    }

    private function change(string $dn): PendingChange
    {
        return new PendingChange(
            changeType: ChangeType::Add,
            dn: new Dn($dn),
            entryUuid: self::UUID,
            authzId: AuthzId::anonymous(),
        );
    }
}
