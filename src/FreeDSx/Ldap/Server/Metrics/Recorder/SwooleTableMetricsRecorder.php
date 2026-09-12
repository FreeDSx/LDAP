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

namespace FreeDSx\Ldap\Server\Metrics\Recorder;

use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\MetricsSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Metrics\Observation\JournalObservation;
use FreeDSx\Ldap\Server\Metrics\Observation\OperationObservation;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\Metrics\Observation\TrafficObservation;
use FreeDSx\Ldap\Server\Metrics\Snapshot\ConnectionMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\JournalMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\LifecycleMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\MetricsSnapshot;
use FreeDSx\Ldap\Server\Metrics\Snapshot\OperationMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\TrafficMetrics;
use FreeDSx\Ldap\Server\Metrics\WorkerScopedMetricsInterface;
use Swoole\Table;

use function is_int;
use function max;
use function str_starts_with;
use function strlen;
use function strpos;
use function substr;

/**
 * Records metrics into shared memory so every worker of a pool contributes to one set of totals.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SwooleTableMetricsRecorder implements
    MetricsRecorderInterface,
    MetricsSnapshotProvider,
    WorkerScopedMetricsInterface
{
    private const COLUMN = 'v';

    /**
     * Keys are truncated past this, which would silently merge two counters into one.
     */
    private const MAX_KEY_LENGTH = 63;

    /**
     * Durations are summed as whole microseconds, since a table column cannot hold a float.
     */
    private const MICROSECONDS = 1_000_000;

    private const LIFECYCLE_STARTED = 'life.started';

    private const LIFECYCLE_RELOAD_AT = 'life.reloadAt';

    private const LIFECYCLE_RELOAD_COUNT = 'life.reloadCount.';

    /**
     * Gauges go up and back down. These must be work scoped to properly track them (workers can be killed).
     */
    private const CONNECTIONS_ACTIVE = 'conn.active.';

    private const CONNECTIONS_TOTAL = 'conn.total';

    private const CONNECTIONS_REJECTED = 'conn.rejected';

    private const CONNECTIONS_WRITE_TIMEOUTS = 'conn.writeTimeouts';

    private const CONNECTIONS_IDLE_TIMEOUTS = 'conn.idleTimeouts';

    private const CONNECTIONS_REQUEST_SIZE = 'conn.requestSizeExceeded';

    private const CONNECTIONS_PROTOCOL_ERRORS = 'conn.protocolErrors';

    private const CONNECTIONS_UNAVAILABLE = 'conn.unavailable';

    private const JOURNAL_PRUNE_SUCCESSES = 'journal.pruneSuccesses';

    private const JOURNAL_PRUNE_FAILURES = 'journal.pruneFailures';

    private const TRAFFIC_SENT = 'traffic.sent';

    private const TRAFFIC_RECEIVED = 'traffic.received';

    private const TRAFFIC_ENTRIES = 'traffic.entries';

    private const OPERATION_COUNT = 'op.n.';

    private const OPERATION_ERROR = 'op.err.';

    private const OPERATION_MICROS = 'op.us.';

    private const OPERATION_IN_PROGRESS = 'op.busy.';

    private const RESULT_CODE = 'rc.';

    private const BIND_METHOD = 'bind.';

    private const SEARCH_SCOPE = 'scope.';

    private const WORKER_PRESENT = 'worker.present.';

    private int $workerId = 0;

    /**
     * @param Table<array{v: int}> $table Must be created before the pool forks, so every worker shares the one mapping.
     */
    public function __construct(private readonly Table $table) {}

    public function beginWorker(int $workerId): void
    {
        $this->workerId = $workerId;

        foreach ($this->table as $key => $row) {
            if (!$this->belongsToWorker($key, $workerId)) {
                continue;
            }

            $this->table->del($key);
        }

        // Reporting for duty is what makes the worker count an observation rather than a prediction.
        $this->set(
            self::WORKER_PRESENT . $workerId,
            1,
        );
    }

    /**
     * Builds the shared table; call before starting a worker pool.
     *
     * @return Table<array{v: int}>
     */
    public static function createTable(int $rows = 4096): Table
    {
        /** @var Table<array{v: int}> $table */
        $table = new Table($rows);
        $table->column(
            self::COLUMN,
            Table::TYPE_INT,
            8,
        );
        $table->create();

        return $table;
    }

    public function operationStarted(OperationType $operation): void
    {
        $this->add(
            $this->inProgressKey($operation->value),
            1,
        );
    }

    public function operationObserved(OperationObservation $observation): void
    {
        $operation = $observation->operation->value;

        $this->add(
            $this->inProgressKey($operation),
            -1,
        );
        $this->add(
            self::OPERATION_COUNT . $operation,
            1,
        );
        $this->add(
            self::OPERATION_MICROS . $operation,
            (int) ($observation->durationSeconds * self::MICROSECONDS),
        );
        $this->add(
            self::RESULT_CODE . $observation->resultCode,
            1,
        );

        if (!$observation->succeeded) {
            $this->add(
                self::OPERATION_ERROR . $operation,
                1,
            );
        }

        if ($observation->bindMethod !== null) {
            $this->add(
                self::BIND_METHOD . $observation->bindMethod,
                1,
            );
        }

        if ($observation->searchScope !== null) {
            $this->add(
                self::SEARCH_SCOPE . $observation->searchScope,
                1,
            );
        }
    }

    public function trafficObserved(TrafficObservation $observation): void
    {
        $this->add(
            self::TRAFFIC_SENT,
            $observation->bytesSent,
        );
        $this->add(
            self::TRAFFIC_RECEIVED,
            $observation->bytesReceived,
        );
        $this->add(
            self::TRAFFIC_ENTRIES,
            $observation->entriesReturned,
        );
    }

    public function connectionObserved(ConnectionObservation $observation): void
    {
        match ($observation) {
            ConnectionObservation::Opened => $this->onOpened(),
            ConnectionObservation::Closed => $this->add($this->activeKey(), -1),
            ConnectionObservation::Rejected => $this->add(self::CONNECTIONS_REJECTED, 1),
            ConnectionObservation::WriteTimeout => $this->add(self::CONNECTIONS_WRITE_TIMEOUTS, 1),
            ConnectionObservation::IdleTimeout => $this->add(self::CONNECTIONS_IDLE_TIMEOUTS, 1),
            ConnectionObservation::RequestSizeExceeded => $this->add(self::CONNECTIONS_REQUEST_SIZE, 1),
            ConnectionObservation::ProtocolError => $this->add(self::CONNECTIONS_PROTOCOL_ERRORS, 1),
            ConnectionObservation::Unavailable => $this->add(self::CONNECTIONS_UNAVAILABLE, 1),
        };
    }

    public function journalObserved(JournalObservation $observation): void
    {
        match ($observation) {
            JournalObservation::PruneSucceeded => $this->add(self::JOURNAL_PRUNE_SUCCESSES, 1),
            JournalObservation::PruneFailed => $this->add(self::JOURNAL_PRUNE_FAILURES, 1),
        };
    }

    /**
     * Every worker reports the same start, so the first to record it wins rather than the last.
     */
    public function serverStarted(int $startedAt): void
    {
        if ($this->get(self::LIFECYCLE_STARTED) === 0) {
            $this->set(
                self::LIFECYCLE_STARTED,
                $startedAt,
            );
        }
    }

    public function serverReloaded(int $reloadedAt): void
    {
        $this->set(
            self::LIFECYCLE_RELOAD_AT,
            $reloadedAt,
        );
        $this->add(
            self::LIFECYCLE_RELOAD_COUNT . $this->workerId,
            1,
        );
    }

    public function snapshot(): MetricsSnapshot
    {
        $counts = [];
        $errors = [];
        $durations = [];
        $resultCodes = [];
        $binds = [];
        $scopes = [];
        $inProgress = [];
        $active = 0;
        $reloadCount = 0;
        $workers = 0;

        foreach ($this->table as $key => $row) {
            $value = $row[self::COLUMN];

            // Each worker keeps its own gauge row, floored on its own, and the pool total is their sum.
            if ($this->isKeyFor($key, self::CONNECTIONS_ACTIVE)) {
                $active += max(0, $value);

                continue;
            }

            if ($this->isKeyFor($key, self::OPERATION_IN_PROGRESS)) {
                $operation = $this->inProgressOperation($key);
                $inProgress[$operation] = ($inProgress[$operation] ?? 0) + max(0, $value);

                continue;
            }

            if ($this->isKeyFor($key, self::LIFECYCLE_RELOAD_COUNT)) {
                $reloadCount = max($reloadCount, $value);

                continue;
            }

            if ($this->isKeyFor($key, self::WORKER_PRESENT)) {
                $workers += $value;

                continue;
            }

            match (true) {
                $this->isKeyFor($key, self::OPERATION_COUNT)
                    => $counts[$this->suffix($key, self::OPERATION_COUNT)] = $value,
                $this->isKeyFor($key, self::OPERATION_ERROR)
                    => $errors[$this->suffix($key, self::OPERATION_ERROR)] = $value,
                $this->isKeyFor($key, self::OPERATION_MICROS)
                    => $durations[$this->suffix($key, self::OPERATION_MICROS)] = $value / self::MICROSECONDS,
                $this->isKeyFor($key, self::RESULT_CODE)
                    => $resultCodes[(int) $this->suffix($key, self::RESULT_CODE)] = $value,
                $this->isKeyFor($key, self::BIND_METHOD)
                    => $binds[$this->suffix($key, self::BIND_METHOD)] = $value,
                $this->isKeyFor($key, self::SEARCH_SCOPE)
                    => $scopes[$this->suffix($key, self::SEARCH_SCOPE)] = $value,
                default => null,
            };
        }

        return new MetricsSnapshot(
            lifecycle: new LifecycleMetrics(
                startedAt: $this->get(self::LIFECYCLE_STARTED),
                lastReloadAt: $this->get(self::LIFECYCLE_RELOAD_AT),
                reloadCount: $reloadCount,
                workers: $workers,
            ),
            connections: new ConnectionMetrics(
                active: $active,
                total: $this->get(self::CONNECTIONS_TOTAL),
                rejected: $this->get(self::CONNECTIONS_REJECTED),
                writeTimeouts: $this->get(self::CONNECTIONS_WRITE_TIMEOUTS),
                idleTimeouts: $this->get(self::CONNECTIONS_IDLE_TIMEOUTS),
                requestSizeExceeded: $this->get(self::CONNECTIONS_REQUEST_SIZE),
                protocolErrors: $this->get(self::CONNECTIONS_PROTOCOL_ERRORS),
                unavailable: $this->get(self::CONNECTIONS_UNAVAILABLE),
            ),
            operations: new OperationMetrics(
                counts: $counts,
                errors: $errors,
                durationSeconds: $durations,
                resultCodeCounts: $resultCodes,
                bindCounts: $binds,
                searchScopeCounts: $scopes,
            ),
            operationsInProgress: $inProgress,
            traffic: new TrafficMetrics(
                bytesSent: $this->get(self::TRAFFIC_SENT),
                bytesReceived: $this->get(self::TRAFFIC_RECEIVED),
                entriesReturned: $this->get(self::TRAFFIC_ENTRIES),
            ),
            journal: new JournalMetrics(
                pruneSuccesses: $this->get(self::JOURNAL_PRUNE_SUCCESSES),
                pruneFailures: $this->get(self::JOURNAL_PRUNE_FAILURES),
            ),
        );
    }

    private function onOpened(): void
    {
        $this->add(
            $this->activeKey(),
            1,
        );
        $this->add(
            self::CONNECTIONS_TOTAL,
            1,
        );
    }

    /**
     * The gauge row this worker owns, which only it adds to and only it clears.
     */
    private function activeKey(): string
    {
        return self::CONNECTIONS_ACTIVE . $this->workerId;
    }

    private function inProgressKey(string $operation): string
    {
        return self::OPERATION_IN_PROGRESS . $this->workerId . '.' . $operation;
    }

    /**
     * Whether a key is one of the gauge rows scoped to the given worker.
     */
    private function belongsToWorker(
        string $key,
        int $workerId,
    ): bool {
        return $key === self::CONNECTIONS_ACTIVE . $workerId
            || $this->isKeyFor($key, self::OPERATION_IN_PROGRESS . $workerId . '.');
    }

    /**
     * Whether a row belongs to the group a prefix names.
     */
    private function isKeyFor(
        string $key,
        string $prefix,
    ): bool {
        return str_starts_with(
            $key,
            $prefix,
        );
    }

    /**
     * Atomically adds to a counter, creating its row on first use.
     */
    private function add(
        string $key,
        int $amount,
    ): void {
        $this->table->incr(
            $this->boundedKey($key),
            self::COLUMN,
            $amount,
        );
    }

    private function set(
        string $key,
        int $value,
    ): void {
        $this->table->set(
            $this->boundedKey($key),
            [self::COLUMN => $value],
        );
    }

    private function get(string $key): int
    {
        $value = $this->table->get(
            $this->boundedKey($key),
            self::COLUMN,
        );

        return is_int($value)
            ? $value
            : 0;
    }

    /**
     * Keeps a key within what the table stores verbatim, since a longer one is truncated without warning.
     */
    private function boundedKey(string $key): string
    {
        return substr($key, 0, self::MAX_KEY_LENGTH);
    }

    private function suffix(
        string $key,
        string $prefix,
    ): string {
        return substr($key, strlen($prefix));
    }

    /**
     * Reads the operation back out of a gauge key, which carries the worker it belongs to ahead of it.
     */
    private function inProgressOperation(string $key): string
    {
        $scoped = $this->suffix($key, self::OPERATION_IN_PROGRESS);
        $separator = strpos($scoped, '.');

        return $separator === false
            ? $scoped
            : substr($scoped, $separator + 1);
    }
}
