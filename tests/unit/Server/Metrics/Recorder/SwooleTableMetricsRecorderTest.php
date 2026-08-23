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

namespace Tests\Unit\FreeDSx\Ldap\Server\Metrics\Recorder;

use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Metrics\Observation\OperationObservation;
use FreeDSx\Ldap\Server\Metrics\Observation\TrafficObservation;
use FreeDSx\Ldap\Server\Metrics\Recorder\SwooleTableMetricsRecorder;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;

final class SwooleTableMetricsRecorderTest extends TestCase
{
    use RequiresExtensionsTrait;

    private SwooleTableMetricsRecorder $subject;

    protected function setUp(): void
    {
        $this->requireSwoole();

        $this->subject = new SwooleTableMetricsRecorder(SwooleTableMetricsRecorder::createTable(1024));
    }

    public function test_it_starts_empty(): void
    {
        $snapshot = $this->subject->snapshot();

        self::assertSame(
            0,
            $snapshot->operations->total(),
        );
        self::assertSame(
            0,
            $snapshot->connections->total,
        );
    }

    public function test_it_counts_operations_by_type(): void
    {
        $this->observe(OperationType::Search);
        $this->observe(OperationType::Search);
        $this->observe(OperationType::Bind);

        $operations = $this->subject->snapshot()->operations;

        self::assertSame(
            2,
            $operations->counts[OperationType::Search->value],
        );
        self::assertSame(
            1,
            $operations->counts[OperationType::Bind->value],
        );
        self::assertSame(
            3,
            $operations->total(),
        );
    }

    public function test_it_counts_only_failed_operations_as_errors(): void
    {
        $this->observe(OperationType::Search);
        $this->observe(
            OperationType::Search,
            succeeded: false,
        );

        $operations = $this->subject->snapshot()->operations;

        self::assertSame(
            1,
            $operations->errors[OperationType::Search->value],
        );
        self::assertSame(
            1,
            $operations->totalErrors(),
        );
    }

    public function test_it_sums_durations_back_into_seconds(): void
    {
        $this->observe(
            OperationType::Search,
            durationSeconds: 0.25,
        );
        $this->observe(
            OperationType::Search,
            durationSeconds: 0.5,
        );

        self::assertEqualsWithDelta(
            0.75,
            $this->subject->snapshot()->operations->durationSeconds[OperationType::Search->value],
            0.000001,
        );
    }

    public function test_it_counts_result_codes_bind_methods_and_scopes(): void
    {
        $this->observe(
            OperationType::Bind,
            resultCode: 49,
            bindMethod: 'simple',
        );
        $this->observe(
            OperationType::Search,
            searchScope: 'subtree',
        );

        $operations = $this->subject->snapshot()->operations;

        self::assertSame(
            1,
            $operations->resultCodeCounts[49],
        );
        self::assertSame(
            1,
            $operations->bindCounts['simple'],
        );
        self::assertSame(
            1,
            $operations->searchScopeCounts['subtree'],
        );
    }

    public function test_an_operation_in_flight_is_counted_until_it_completes(): void
    {
        $this->subject->operationStarted(OperationType::Search);
        $this->subject->operationStarted(OperationType::Search);

        self::assertSame(
            2,
            $this->subject->snapshot()->operationsInProgress[OperationType::Search->value],
        );

        $this->observe(OperationType::Search);

        self::assertSame(
            1,
            $this->subject->snapshot()->operationsInProgress[OperationType::Search->value],
        );
    }

    public function test_an_unmatched_completion_does_not_report_a_negative_gauge(): void
    {
        // A worker killed mid-operation leaves the decrement without its increment.
        $this->observe(OperationType::Search);

        self::assertSame(
            0,
            $this->subject->snapshot()->operationsInProgress[OperationType::Search->value],
        );
    }

    public function test_it_tracks_connections_opening_and_closing(): void
    {
        $this->subject->connectionObserved(ConnectionObservation::Opened);
        $this->subject->connectionObserved(ConnectionObservation::Opened);
        $this->subject->connectionObserved(ConnectionObservation::Closed);
        $this->subject->connectionObserved(ConnectionObservation::Rejected);

        $connections = $this->subject->snapshot()->connections;

        self::assertSame(
            2,
            $connections->total,
        );
        self::assertSame(
            1,
            $connections->active,
        );
        self::assertSame(
            1,
            $connections->rejected,
        );
    }

    public function test_closing_more_connections_than_were_opened_does_not_report_a_negative_gauge(): void
    {
        $this->subject->connectionObserved(ConnectionObservation::Closed);

        self::assertSame(
            0,
            $this->subject->snapshot()->connections->active,
        );
    }

    public function test_it_accumulates_traffic(): void
    {
        $this->subject->trafficObserved(new TrafficObservation(
            bytesSent: 100,
            bytesReceived: 50,
            entriesReturned: 3,
        ));
        $this->subject->trafficObserved(new TrafficObservation(
            bytesSent: 20,
            bytesReceived: 10,
            entriesReturned: 1,
        ));

        $traffic = $this->subject->snapshot()->traffic;

        self::assertSame(
            120,
            $traffic->bytesSent,
        );
        self::assertSame(
            60,
            $traffic->bytesReceived,
        );
        self::assertSame(
            4,
            $traffic->entriesReturned,
        );
    }

    public function test_the_first_worker_to_report_the_start_time_wins(): void
    {
        $this->subject->serverStarted(1000);
        $this->subject->serverStarted(2000);

        self::assertSame(
            1000,
            $this->subject->snapshot()->lifecycle->startedAt,
        );
    }

    public function test_reloads_are_counted_and_the_latest_time_kept(): void
    {
        $this->subject->serverReloaded(1000);
        $this->subject->serverReloaded(2000);

        $lifecycle = $this->subject->snapshot()->lifecycle;

        self::assertSame(
            2,
            $lifecycle->reloadCount,
        );
        self::assertSame(
            2000,
            $lifecycle->lastReloadAt,
        );
    }

    public function test_two_recorders_on_one_table_report_combined_totals(): void
    {
        // Stands in for two workers sharing the table the pool created before forking.
        $table = SwooleTableMetricsRecorder::createTable(1024);
        $workerOne = new SwooleTableMetricsRecorder($table);
        $workerTwo = new SwooleTableMetricsRecorder($table);

        $workerOne->connectionObserved(ConnectionObservation::Opened);
        $workerTwo->connectionObserved(ConnectionObservation::Opened);
        $workerOne->operationObserved(new OperationObservation(
            operation: OperationType::Search,
            succeeded: true,
            durationSeconds: 0.1,
            resultCode: 0,
        ));
        $workerTwo->operationObserved(new OperationObservation(
            operation: OperationType::Search,
            succeeded: true,
            durationSeconds: 0.1,
            resultCode: 0,
        ));

        $snapshot = $workerOne->snapshot();

        self::assertSame(
            2,
            $snapshot->connections->total,
        );
        self::assertSame(
            2,
            $snapshot->operations->counts[OperationType::Search->value],
        );
    }

    private function observe(
        OperationType $operation,
        bool $succeeded = true,
        float $durationSeconds = 0.01,
        int $resultCode = 0,
        ?string $bindMethod = null,
        ?string $searchScope = null,
    ): void {
        $this->subject->operationObserved(new OperationObservation(
            operation: $operation,
            succeeded: $succeeded,
            durationSeconds: $durationSeconds,
            resultCode: $resultCode,
            bindMethod: $bindMethod,
            searchScope: $searchScope,
        ));
    }
}
