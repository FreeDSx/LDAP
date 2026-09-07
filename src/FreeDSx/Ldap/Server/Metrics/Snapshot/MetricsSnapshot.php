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

namespace FreeDSx\Ldap\Server\Metrics\Snapshot;

/**
 * An immutable point-in-time view of the collected server metrics, grouped by area.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class MetricsSnapshot
{
    /**
     * @param array<string, int> $operationsInProgress In-flight count per operation type (a live gauge, not a counter).
     */
    public function __construct(
        public LifecycleMetrics $lifecycle = new LifecycleMetrics(),
        public ConnectionMetrics $connections = new ConnectionMetrics(),
        public OperationMetrics $operations = new OperationMetrics(),
        public array $operationsInProgress = [],
        public TrafficMetrics $traffic = new TrafficMetrics(),
        public JournalMetrics $journal = new JournalMetrics(),
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'lifecycle' => $this->lifecycle->toArray(),
            'connections' => $this->connections->toArray(),
            'operations' => $this->operations->toArray(),
            'operations_in_progress' => $this->operationsInProgress,
            'traffic' => $this->traffic->toArray(),
            'journal' => $this->journal->toArray(),
        ];
    }

    /**
     * @param array<array-key, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            lifecycle: LifecycleMetrics::fromArray(self::section(
                $data,
                'lifecycle',
            )),
            connections: ConnectionMetrics::fromArray(self::section(
                $data,
                'connections',
            )),
            operations: OperationMetrics::fromArray(self::section(
                $data,
                'operations',
            )),
            operationsInProgress: SnapshotValue::toIntMap($data['operations_in_progress'] ?? null),
            traffic: TrafficMetrics::fromArray(self::section(
                $data,
                'traffic',
            )),
            journal: JournalMetrics::fromArray(self::section(
                $data,
                'journal',
            )),
        );
    }

    /**
     * @param array<array-key, mixed> $data
     * @return array<array-key, mixed>
     */
    private static function section(
        array $data,
        string $key,
    ): array {
        $section = $data[$key] ?? [];

        return is_array($section)
            ? $section
            : [];
    }
}
