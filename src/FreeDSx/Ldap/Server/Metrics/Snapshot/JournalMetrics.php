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
 * Change-journal retention counters.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class JournalMetrics
{
    public function __construct(
        public int $pruneSuccesses = 0,
        public int $pruneFailures = 0,
    ) {}

    /**
     * @return array<string, int>
     */
    public function toArray(): array
    {
        return [
            'prune_successes' => $this->pruneSuccesses,
            'prune_failures' => $this->pruneFailures,
        ];
    }

    /**
     * @param array<array-key, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            pruneSuccesses: SnapshotValue::toInt($data['prune_successes'] ?? null),
            pruneFailures: SnapshotValue::toInt($data['prune_failures'] ?? null),
        );
    }
}
