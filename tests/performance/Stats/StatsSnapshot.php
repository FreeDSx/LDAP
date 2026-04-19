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

namespace Tests\Performance\FreeDSx\Ldap\Stats;

/**
 * Frozen result of a load run.
 */
final class StatsSnapshot
{
    /**
     * @param array<string, array<int, int>> $samples op -> nanosecond latencies
     * @param array<string, int> $counts op -> total successes
     * @param array<string, int> $errors op -> total errors
     * @param array<string, array<string, int>> $errorClasses op -> exception class -> count
     * @param array<string, int> $substituted "fromOp->toOp" -> count
     */
    public function __construct(
        public readonly array $samples,
        public readonly array $counts,
        public readonly array $errors,
        public readonly array $errorClasses,
        public readonly array $substituted,
        public readonly float $elapsedSeconds,
    ) {
    }

    /**
     * @return list<string> ops ordered by total activity (successes + errors) descending
     */
    public function operations(): array
    {
        $allOps = array_unique(array_merge(
            array_keys($this->counts),
            array_keys($this->errors),
        ));

        usort($allOps, fn ($a, $b) => $this->activity($b) <=> $this->activity($a));

        return $allOps;
    }

    public function successCount(string $op): int
    {
        return $this->counts[$op] ?? 0;
    }

    public function errorCount(string $op): int
    {
        return $this->errors[$op] ?? 0;
    }

    public function throughput(string $op): float
    {
        return $this->successCount($op) / $this->elapsedSeconds;
    }

    /**
     * @return array{min: int, max: int, mean: int, p50: int, p95: int, p99: int}
     */
    public function latencyStats(string $op): array
    {
        $sorted = $this->samples[$op] ?? [];

        if ($sorted === []) {
            return ['min' => 0, 'max' => 0, 'mean' => 0, 'p50' => 0, 'p95' => 0, 'p99' => 0];
        }

        sort($sorted);
        $n = count($sorted);

        return [
            'min' => $sorted[0],
            'max' => $sorted[$n - 1],
            'mean' => (int) (array_sum($sorted) / $n),
            'p50' => self::percentile($sorted, 0.50),
            'p95' => self::percentile($sorted, 0.95),
            'p99' => self::percentile($sorted, 0.99),
        ];
    }

    public function totalSuccess(): int
    {
        return array_sum($this->counts);
    }

    public function totalErrors(): int
    {
        return array_sum($this->errors);
    }

    public function overallThroughput(): float
    {
        return $this->totalSuccess() / $this->elapsedSeconds;
    }

    /**
     * @return list<array{class: string, count: int}> top N exception classes across all ops
     */
    public function topErrorClasses(int $limit = 3): array
    {
        $totals = [];
        foreach ($this->errorClasses as $classes) {
            foreach ($classes as $class => $count) {
                $totals[$class] = ($totals[$class] ?? 0) + $count;
            }
        }

        arsort($totals);
        $top = array_slice($totals, 0, $limit, true);

        $result = [];
        foreach ($top as $class => $count) {
            $result[] = ['class' => $class, 'count' => $count];
        }

        return $result;
    }

    private function activity(string $op): int
    {
        return ($this->counts[$op] ?? 0) + ($this->errors[$op] ?? 0);
    }

    /**
     * @param array<int, int> $sorted values in ascending order, keyed 0..n-1
     */
    private static function percentile(
        array $sorted,
        float $p
    ): int {
        $n = count($sorted);
        $idx = (int) floor($p * ($n - 1));

        return $sorted[$idx];
    }
}
