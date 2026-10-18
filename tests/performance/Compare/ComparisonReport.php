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

namespace Tests\Performance\FreeDSx\Ldap\Compare;

use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Output\OutputInterface;
use Tests\Performance\FreeDSx\Ldap\Stats\StatsSnapshot;
use Tests\Performance\FreeDSx\Ldap\Workload\WorkloadMix;

/**
 * Side-by-side renderer for a target LDAP server vs the source server (FreeDSx by default) benchmark run.
 */
final class ComparisonReport
{
    /**
     * @param list<string> $targetAccessProblems What the target's access control got wrong for its run identity.
     * @param list<string> $sourceAccessProblems What the source's access control got wrong for its run identity.
     */
    public function __construct(
        private readonly ?StatsSnapshot $target,
        private readonly ?StatsSnapshot $source,
        private readonly string $format,
        private readonly string $targetLabel = 'Target',
        private readonly string $sourceLabel = 'FreeDSx',
        private readonly array $targetAccessProblems = [],
        private readonly array $sourceAccessProblems = [],
    ) {}

    public function render(OutputInterface $output): void
    {
        if ($this->format === 'json') {
            $output->writeln($this->renderJson());

            return;
        }

        $this->renderText($output);

        foreach ($this->invalidReasons() as $reason) {
            $output->writeln(sprintf(
                '<error>INVALID: %s</error>',
                $reason,
            ));
        }
    }

    /**
     * @return list<string>
     */
    public function invalidReasons(): array
    {
        $reasons = [];
        $sides = [
            [$this->targetLabel, $this->target, $this->targetAccessProblems],
            [$this->sourceLabel, $this->source, $this->sourceAccessProblems],
        ];

        foreach ($sides as [$label, $snapshot, $accessProblems]) {
            $barren = $snapshot?->opsReturningNothing(WorkloadMix::ENTRY_OPS) ?? [];

            if ($barren !== []) {
                $reasons[] = sprintf(
                    '%s returned no entries for %s.',
                    $label,
                    implode(
                        ', ',
                        $barren,
                    ),
                );
            }

            foreach ($accessProblems as $problem) {
                $reasons[] = sprintf(
                    '%s %s.',
                    $label,
                    $problem,
                );
            }
        }

        return $reasons;
    }

    /**
     * @return list<string>
     */
    private function headers(): array
    {
        return [
            'Operation',
            "{$this->targetLabel} ops/s",
            "{$this->sourceLabel} ops/s",
            "Ratio ({$this->sourceLabel}/{$this->targetLabel})",
            "{$this->targetLabel} p99",
            "{$this->sourceLabel} p99",
            "{$this->targetLabel} err",
            "{$this->sourceLabel} err",
        ];
    }

    private function renderText(OutputInterface $output): void
    {
        $output->writeln('');
        $output->writeln('Side-by-side comparison');
        $output->writeln('=======================');

        if ($this->target === null) {
            $output->writeln(sprintf('%s run was skipped.', $this->targetLabel));
        }
        if ($this->source === null) {
            $output->writeln(sprintf('%s run was skipped.', $this->sourceLabel));
        }

        if ($this->target === null || $this->source === null) {
            return;
        }

        $table = new Table($output);
        $table->setHeaders($this->headers());

        foreach ($this->unionOps() as $op) {
            $table->addRow($this->buildRow($op));
        }

        $table->render();

        $targetTotal = $this->target->overallThroughput();
        $sourceTotal = $this->source->overallThroughput();

        $output->writeln('');
        $output->writeln(sprintf(
            'Overall throughput: %s %s ops/s  |  %s %s ops/s  |  ratio %s',
            $this->targetLabel,
            number_format($targetTotal, 1),
            $this->sourceLabel,
            number_format($sourceTotal, 1),
            $this->formatRatio($sourceTotal, $targetTotal),
        ));
        $output->writeln(sprintf(
            'Errors: %s %d  |  %s %d',
            $this->targetLabel,
            $this->target->totalErrors(),
            $this->sourceLabel,
            $this->source->totalErrors(),
        ));
        $output->writeln(sprintf(
            'Elapsed: %s %.1fs  |  %s %.1fs',
            $this->targetLabel,
            $this->target->elapsedSeconds,
            $this->sourceLabel,
            $this->source->elapsedSeconds,
        ));
    }

    /**
     * @return list<string>
     */
    private function buildRow(string $op): array
    {
        $targetThr = $this->target?->throughput($op) ?? 0.0;
        $sourceThr = $this->source?->throughput($op) ?? 0.0;

        $targetStats = $this->target?->latencyStats($op) ?? ['p99' => 0];
        $sourceStats = $this->source?->latencyStats($op) ?? ['p99' => 0];

        return [
            $op,
            number_format($targetThr, 2),
            number_format($sourceThr, 2),
            $this->formatRatio($sourceThr, $targetThr),
            self::formatNanos($targetStats['p99']),
            self::formatNanos($sourceStats['p99']),
            (string) ($this->target?->errorCount($op) ?? 0),
            (string) ($this->source?->errorCount($op) ?? 0),
        ];
    }

    /**
     * @return list<string>
     */
    private function unionOps(): array
    {
        $ops = array_merge(
            $this->target?->operations() ?? [],
            $this->source?->operations() ?? [],
        );

        return array_values(array_unique($ops));
    }

    private function renderJson(): string
    {
        return json_encode(
            [
                'target' => $this->snapshotToArray($this->target),
                'source' => $this->snapshotToArray($this->source),
                'invalid' => $this->invalidReasons(),
            ],
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
        );
    }

    /**
     * @return array<string, mixed>|null
     */
    private function snapshotToArray(?StatsSnapshot $snapshot): ?array
    {
        if ($snapshot === null) {
            return null;
        }

        $ops = [];
        foreach ($snapshot->operations() as $op) {
            $ops[$op] = [
                'count' => $snapshot->successCount($op),
                'errors' => $snapshot->errorCount($op),
                'throughput' => $snapshot->throughput($op),
                'latency_ns' => $snapshot->latencyStats($op),
            ];
        }

        return [
            'elapsed_seconds' => $snapshot->elapsedSeconds,
            'operations' => $ops,
            'totals' => [
                'success' => $snapshot->totalSuccess(),
                'errors' => $snapshot->totalErrors(),
                'throughput' => $snapshot->overallThroughput(),
            ],
        ];
    }

    private function formatRatio(
        float $numerator,
        float $denominator,
    ): string {
        if ($denominator <= 0.0) {
            return '-';
        }

        return sprintf('%.2fx', $numerator / $denominator);
    }

    private static function formatNanos(int $nanos): string
    {
        if ($nanos === 0) {
            return '-';
        }

        return sprintf('%.2fms', $nanos / 1_000_000);
    }
}
