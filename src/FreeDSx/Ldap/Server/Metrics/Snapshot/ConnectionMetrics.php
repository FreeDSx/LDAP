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
 * Connection metrics: the live gauge plus cumulative lifecycle counters.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ConnectionMetrics
{
    public function __construct(
        public int $active = 0,
        public int $total = 0,
        public int $rejected = 0,
        public int $writeTimeouts = 0,
        public int $idleTimeouts = 0,
        public int $requestSizeExceeded = 0,
        public int $protocolErrors = 0,
        public int $unavailable = 0,
    ) {}

    /**
     * @return array<string, int>
     */
    public function toArray(): array
    {
        return [
            'active' => $this->active,
            'total' => $this->total,
            'rejected' => $this->rejected,
            'write_timeouts' => $this->writeTimeouts,
            'idle_timeouts' => $this->idleTimeouts,
            'request_size_exceeded' => $this->requestSizeExceeded,
            'protocol_errors' => $this->protocolErrors,
            'unavailable' => $this->unavailable,
        ];
    }

    /**
     * @param array<array-key, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            active: SnapshotValue::toInt($data['active'] ?? null),
            total: SnapshotValue::toInt($data['total'] ?? null),
            rejected: SnapshotValue::toInt($data['rejected'] ?? null),
            writeTimeouts: SnapshotValue::toInt($data['write_timeouts'] ?? null),
            idleTimeouts: SnapshotValue::toInt($data['idle_timeouts'] ?? null),
            requestSizeExceeded: SnapshotValue::toInt($data['request_size_exceeded'] ?? null),
            protocolErrors: SnapshotValue::toInt($data['protocol_errors'] ?? null),
            unavailable: SnapshotValue::toInt($data['unavailable'] ?? null),
        );
    }
}
