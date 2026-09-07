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
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionPolicy;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionSweeper;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

final class RetentionSweeperTest extends TestCase
{
    private RecordingLogger $logger;

    private EventLogger $eventLogger;

    private FrozenClock $clock;

    private InMemoryChangeJournal $journal;

    protected function setUp(): void
    {
        $this->logger = new RecordingLogger();
        $this->eventLogger = new EventLogger(
            $this->logger,
            EventLogPolicy::default(),
        );
        $this->clock = FrozenClock::fromString('2025-05-15T12:00:00');
        $this->journal = new InMemoryChangeJournal(
            new ReplicaId('node-a'),
            $this->clock,
        );
    }

    public function test_sweep_prunes_to_the_record_cap_and_records_the_outcome(): void
    {
        $this->appendChanges(5);
        $sweeper = new RetentionSweeper(
            $this->journal,
            new RetentionPolicy(maxRecords: 2),
            $this->eventLogger,
        );

        $removed = $sweeper->sweep();

        self::assertSame(
            3,
            $removed,
        );
        self::assertCount(
            2,
            iterator_to_array($this->journal->read()),
        );

        $event = $this->onlyRecordFor(ServerEvent::JournalPruned);
        self::assertSame(
            3,
            $event['context'][EventContext::REMOVED],
        );
        self::assertIsFloat($event['context'][EventContext::DURATION_SECONDS]);
        self::assertGreaterThanOrEqual(
            0.0,
            $event['context'][EventContext::DURATION_SECONDS],
        );
    }

    public function test_sweep_prunes_records_past_the_age_horizon(): void
    {
        $this->appendChanges(1);
        $this->clock->setTo($this->clock->now()->modify('+100 seconds'));
        $this->appendChanges(1);
        $sweeper = new RetentionSweeper(
            $this->journal,
            new RetentionPolicy(maxAgeSeconds: 60),
            $this->eventLogger,
        );

        $removed = $sweeper->sweep();

        self::assertSame(
            1,
            $removed,
        );
        self::assertCount(
            1,
            iterator_to_array($this->journal->read()),
        );
    }

    public function test_sweep_with_no_limits_prunes_nothing_and_records_no_event(): void
    {
        $this->appendChanges(3);
        $sweeper = new RetentionSweeper(
            $this->journal,
            new RetentionPolicy(),
            $this->eventLogger,
        );

        $removed = $sweeper->sweep();

        self::assertSame(
            0,
            $removed,
        );
        self::assertSame(
            [],
            $this->recordsFor(ServerEvent::JournalPruned),
        );
    }

    public function test_sweep_swallows_a_prune_failure_and_records_it(): void
    {
        $journal = $this->createMock(ChangeJournalInterface::class);
        $journal->method('prune')
            ->willThrowException(new RuntimeException('boom'));
        $sweeper = new RetentionSweeper(
            $journal,
            new RetentionPolicy(maxRecords: 1),
            $this->eventLogger,
        );

        $removed = $sweeper->sweep();

        self::assertSame(
            0,
            $removed,
        );
        self::assertCount(
            1,
            $this->recordsFor(ServerEvent::JournalPruneFailed),
        );
    }

    public function test_a_prune_failure_is_counted_where_an_operator_can_see_it_without_a_logger(): void
    {
        $metrics = new InMemoryMetricsRecorder();
        $journal = $this->createMock(ChangeJournalInterface::class);
        $journal->method('prune')
            ->willThrowException(new RuntimeException('boom'));
        $sweeper = new RetentionSweeper(
            $journal,
            new RetentionPolicy(maxRecords: 1),
            new EventLogger(null),
            $metrics,
        );

        $sweeper->sweep();

        self::assertSame(
            1,
            $metrics->snapshot()->journal->pruneFailures,
        );
        self::assertSame(
            0,
            $metrics->snapshot()->journal->pruneSuccesses,
        );
    }

    public function test_a_successful_sweep_is_counted_too(): void
    {
        $metrics = new InMemoryMetricsRecorder();
        $this->appendChanges(3);
        $sweeper = new RetentionSweeper(
            $this->journal,
            new RetentionPolicy(maxRecords: 1),
            new EventLogger(null),
            $metrics,
        );

        $sweeper->sweep();

        self::assertSame(
            1,
            $metrics->snapshot()->journal->pruneSuccesses,
        );
        self::assertSame(
            0,
            $metrics->snapshot()->journal->pruneFailures,
        );
    }

    public function test_it_is_sweepable_in_a_single_process_regardless_of_journal_scope(): void
    {
        $journal = $this->journalSharing(false);

        self::assertTrue(RetentionSweeper::isSweepable(
            new RetentionPolicy(maxRecords: 1),
            $journal,
            true,
        ));
    }

    public function test_it_is_sweepable_when_forking_only_for_a_cross_process_journal(): void
    {
        self::assertTrue(RetentionSweeper::isSweepable(
            new RetentionPolicy(maxRecords: 1),
            $this->journalSharing(true),
            false,
        ));
        self::assertFalse(RetentionSweeper::isSweepable(
            new RetentionPolicy(maxRecords: 1),
            $this->journalSharing(false),
            false,
        ));
    }

    public function test_it_is_never_sweepable_without_a_limit(): void
    {
        self::assertFalse(RetentionSweeper::isSweepable(
            new RetentionPolicy(),
            $this->journalSharing(true),
            true,
        ));
    }

    private function journalSharing(bool $shares): ChangeJournalInterface
    {
        $journal = $this->createMock(ChangeJournalInterface::class);
        $journal->method('sharesAcrossProcesses')
            ->willReturn($shares);

        return $journal;
    }

    private function appendChanges(int $count): void
    {
        for ($i = 1; $i <= $count; $i++) {
            $this->journal->append(new PendingChange(
                changeType: ChangeType::Add,
                dn: new Dn("cn=entry-{$i},dc=example,dc=com"),
                entryUuid: '11111111-1111-4111-8111-111111111111',
                authzId: AuthzId::anonymous(),
            ));
        }
    }

    /**
     * @return list<array{level: string, message: string, context: array<string, mixed>}>
     */
    private function recordsFor(ServerEvent $event): array
    {
        return array_values(array_filter(
            $this->logger->records,
            static fn(array $record): bool => $record['message'] === $event->value,
        ));
    }

    /**
     * @return array{level: string, message: string, context: array<string, mixed>}
     */
    private function onlyRecordFor(ServerEvent $event): array
    {
        $records = $this->recordsFor($event);
        self::assertCount(
            1,
            $records,
        );

        return $records[0];
    }
}
