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

use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\MetricsSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\Observation\OperationObservation;
use FreeDSx\Ldap\Server\Metrics\Observation\TrafficObservation;
use FreeDSx\Ldap\Server\Metrics\Rollup\MetricsDelta;
use FreeDSx\Ldap\Server\Metrics\Rollup\MetricsRollupInterface;
use FreeDSx\Ldap\Server\Metrics\Snapshot\ConnectionMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\LifecycleMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\MetricsSnapshot;
use FreeDSx\Ldap\Server\Metrics\Snapshot\OperationMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\TrafficMetrics;

use function max;

/**
 * Accumulates metrics in process memory and serves them as a snapshot.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class InMemoryMetricsRecorder implements MetricsRecorderInterface, MetricsSnapshotProvider, MetricsRollupInterface
{
    private int $startedAt = 0;

    private int $lastReloadAt = 0;

    /**
     * @var int<0, max>
     */
    private int $reloadCount = 0;

    /**
     * @var int<0, max>
     */
    private int $activeConnections = 0;

    /**
     * @var int<0, max>
     */
    private int $totalConnections = 0;

    /**
     * @var int<0, max>
     */
    private int $rejectedConnections = 0;

    /**
     * @var int<0, max>
     */
    private int $writeTimeouts = 0;

    /**
     * @var int<0, max>
     */
    private int $idleTimeouts = 0;

    /**
     * @var int<0, max>
     */
    private int $requestSizeExceeded = 0;

    /**
     * @var int<0, max>
     */
    private int $protocolErrors = 0;

    /**
     * @var int<0, max>
     */
    private int $unavailable = 0;

    /**
     * @var array<string, int<0, max>>
     */
    private array $operationCounts = [];

    /**
     * @var array<string, int<0, max>>
     */
    private array $operationErrors = [];

    /**
     * @var array<string, float>
     */
    private array $operationDurationSeconds = [];

    /**
     * @var array<int, int<0, max>>
     */
    private array $resultCodeCounts = [];

    /**
     * @var array<string, int<0, max>>
     */
    private array $bindCounts = [];

    /**
     * @var array<string, int<0, max>>
     */
    private array $searchScopeCounts = [];

    /**
     * @var array<string, int<1, max>> In-flight count per operation type; entries are pruned when they reach zero.
     */
    private array $operationsInProgress = [];

    /**
     * @var int<0, max>
     */
    private int $bytesSent = 0;

    /**
     * @var int<0, max>
     */
    private int $bytesReceived = 0;

    /**
     * @var int<0, max>
     */
    private int $entriesReturned = 0;

    public function trafficObserved(TrafficObservation $observation): void
    {
        $this->bytesSent = max(
            0,
            $this->bytesSent + $observation->bytesSent,
        );
        $this->bytesReceived = max(
            0,
            $this->bytesReceived + $observation->bytesReceived,
        );
        $this->entriesReturned = max(
            0,
            $this->entriesReturned + $observation->entriesReturned,
        );
    }

    public function operationStarted(OperationType $operation): void
    {
        $this->operationsInProgress[$operation->value] = ($this->operationsInProgress[$operation->value] ?? 0) + 1;
    }

    public function operationObserved(OperationObservation $observation): void
    {
        $this->clearInProgress($observation->operation);
        $operation = $observation->operation->value;
        $this->operationCounts[$operation] = ($this->operationCounts[$operation] ?? 0) + 1;
        $this->operationDurationSeconds[$operation] = ($this->operationDurationSeconds[$operation] ?? 0.0)
            + $observation->durationSeconds;
        $this->resultCodeCounts[$observation->resultCode] = ($this->resultCodeCounts[$observation->resultCode] ?? 0) + 1;

        if (!$observation->succeeded) {
            $this->operationErrors[$operation] = ($this->operationErrors[$operation] ?? 0) + 1;
        }

        if ($observation->bindMethod !== null) {
            $this->bindCounts[$observation->bindMethod] = ($this->bindCounts[$observation->bindMethod] ?? 0) + 1;
        }

        if ($observation->searchScope !== null) {
            $this->searchScopeCounts[$observation->searchScope] = ($this->searchScopeCounts[$observation->searchScope] ?? 0) + 1;
        }
    }

    public function connectionObserved(ConnectionObservation $observation): void
    {
        match ($observation) {
            ConnectionObservation::Opened => $this->onOpened(),
            ConnectionObservation::Closed => $this->activeConnections = max(0, $this->activeConnections - 1),
            ConnectionObservation::Rejected => $this->rejectedConnections++,
            ConnectionObservation::WriteTimeout => $this->writeTimeouts++,
            ConnectionObservation::IdleTimeout => $this->idleTimeouts++,
            ConnectionObservation::RequestSizeExceeded => $this->requestSizeExceeded++,
            ConnectionObservation::ProtocolError => $this->protocolErrors++,
            ConnectionObservation::Unavailable => $this->unavailable++,
        };
    }

    public function serverStarted(int $startedAt): void
    {
        $this->startedAt = $startedAt;
    }

    public function serverReloaded(int $reloadedAt): void
    {
        $this->lastReloadAt = $reloadedAt;
        $this->reloadCount++;
    }

    public function snapshot(): MetricsSnapshot
    {
        return new MetricsSnapshot(
            new LifecycleMetrics(
                $this->startedAt,
                $this->lastReloadAt,
                $this->reloadCount,
            ),
            new ConnectionMetrics(
                $this->activeConnections,
                $this->totalConnections,
                $this->rejectedConnections,
                $this->writeTimeouts,
                $this->idleTimeouts,
                $this->requestSizeExceeded,
                $this->protocolErrors,
                $this->unavailable,
            ),
            $this->operationMetrics(),
            $this->operationsInProgress,
            $this->trafficMetrics(),
        );
    }

    public function takeDelta(): MetricsDelta
    {
        $delta = new MetricsDelta(
            $this->operationMetrics(),
            $this->trafficMetrics(),
        );

        $this->resetDelta();

        return $delta;
    }

    public function resetDelta(): void
    {
        $this->operationCounts = [];
        $this->operationErrors = [];
        $this->operationDurationSeconds = [];
        $this->resultCodeCounts = [];
        $this->bindCounts = [];
        $this->searchScopeCounts = [];
        $this->bytesSent = 0;
        $this->bytesReceived = 0;
        $this->entriesReturned = 0;
    }

    public function mergeDelta(MetricsDelta $delta): void
    {
        $this->mergeOperations($delta->operations);
        $this->mergeTraffic($delta->traffic);
    }

    private function operationMetrics(): OperationMetrics
    {
        return new OperationMetrics(
            $this->operationCounts,
            $this->operationErrors,
            $this->operationDurationSeconds,
            $this->resultCodeCounts,
            $this->bindCounts,
            $this->searchScopeCounts,
        );
    }

    private function trafficMetrics(): TrafficMetrics
    {
        return new TrafficMetrics(
            $this->bytesSent,
            $this->bytesReceived,
            $this->entriesReturned,
        );
    }

    /**
     * Decrement, and prune at zero, the in-flight gauge for a completed operation type.
     */
    private function clearInProgress(OperationType $operation): void
    {
        $key = $operation->value;

        if (!isset($this->operationsInProgress[$key])) {
            return;
        }

        $remaining = $this->operationsInProgress[$key] - 1;

        if ($remaining <= 0) {
            unset($this->operationsInProgress[$key]);

            return;
        }

        $this->operationsInProgress[$key] = $remaining;
    }

    private function mergeOperations(OperationMetrics $delta): void
    {
        foreach ($delta->counts as $operation => $count) {
            $this->operationCounts[$operation] = max(
                0,
                ($this->operationCounts[$operation] ?? 0) + $count,
            );
        }

        foreach ($delta->errors as $operation => $count) {
            $this->operationErrors[$operation] = max(
                0,
                ($this->operationErrors[$operation] ?? 0) + $count,
            );
        }

        foreach ($delta->durationSeconds as $operation => $seconds) {
            $this->operationDurationSeconds[$operation] = ($this->operationDurationSeconds[$operation] ?? 0.0) + $seconds;
        }

        foreach ($delta->resultCodeCounts as $code => $count) {
            $this->resultCodeCounts[$code] = max(
                0,
                ($this->resultCodeCounts[$code] ?? 0) + $count,
            );
        }

        foreach ($delta->bindCounts as $method => $count) {
            $this->bindCounts[$method] = max(
                0,
                ($this->bindCounts[$method] ?? 0) + $count,
            );
        }

        foreach ($delta->searchScopeCounts as $scope => $count) {
            $this->searchScopeCounts[$scope] = max(
                0,
                ($this->searchScopeCounts[$scope] ?? 0) + $count,
            );
        }
    }

    private function mergeTraffic(TrafficMetrics $delta): void
    {
        $this->bytesSent = max(
            0,
            $this->bytesSent + $delta->bytesSent,
        );
        $this->bytesReceived = max(
            0,
            $this->bytesReceived + $delta->bytesReceived,
        );
        $this->entriesReturned = max(
            0,
            $this->entriesReturned + $delta->entriesReturned,
        );
    }

    private function onOpened(): void
    {
        $this->activeConnections++;
        $this->totalConnections++;
    }
}
