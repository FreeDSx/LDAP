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

/**
 * Side-by-side renderer for an external LDAP target vs FreeDSx benchmark run.
 */
final class ComparisonReport
{
    private const HEADERS = [
        'Operation',
        'Target ops/s',
        'FreeDSx ops/s',
        'Ratio (FreeDSx/Target)',
        'Target p99',
        'FreeDSx p99',
        'Target err',
        'FD err',
    ];

    public function __construct(
        private readonly ?StatsSnapshot $target,
        private readonly ?StatsSnapshot $freedsx,
        private readonly string $format,
    ) {
    }

    public function render(OutputInterface $output): void
    {
        if ($this->format === 'json') {
            $output->writeln($this->renderJson());

            return;
        }

        $this->renderText($output);
    }

    private function renderText(OutputInterface $output): void
    {
        $output->writeln('');
        $output->writeln('Side-by-side comparison');
        $output->writeln('=======================');

        if ($this->target === null) {
            $output->writeln('Target run was skipped.');
        }
        if ($this->freedsx === null) {
            $output->writeln('FreeDSx run was skipped.');
        }

        if ($this->target === null || $this->freedsx === null) {
            return;
        }

        $table = new Table($output);
        $table->setHeaders(self::HEADERS);

        foreach ($this->unionOps() as $op) {
            $table->addRow($this->buildRow($op));
        }

        $table->render();

        $targetTotal = $this->target->overallThroughput();
        $fdTotal = $this->freedsx->overallThroughput();

        $output->writeln('');
        $output->writeln(sprintf(
            'Overall throughput: Target %s ops/s  |  FreeDSx %s ops/s  |  ratio %s',
            number_format($targetTotal, 1),
            number_format($fdTotal, 1),
            $this->formatRatio($fdTotal, $targetTotal),
        ));
        $output->writeln(sprintf(
            'Errors: Target %d  |  FreeDSx %d',
            $this->target->totalErrors(),
            $this->freedsx->totalErrors(),
        ));
        $output->writeln(sprintf(
            'Elapsed: Target %.1fs  |  FreeDSx %.1fs',
            $this->target->elapsedSeconds,
            $this->freedsx->elapsedSeconds,
        ));
    }

    /**
     * @return list<string>
     */
    private function buildRow(string $op): array
    {
        $targetThr = $this->target?->throughput($op) ?? 0.0;
        $fdThr = $this->freedsx?->throughput($op) ?? 0.0;

        $targetStats = $this->target?->latencyStats($op) ?? ['p99' => 0];
        $fdStats = $this->freedsx?->latencyStats($op) ?? ['p99' => 0];

        return [
            $op,
            number_format($targetThr, 2),
            number_format($fdThr, 2),
            $this->formatRatio($fdThr, $targetThr),
            self::formatNanos($targetStats['p99']),
            self::formatNanos($fdStats['p99']),
            (string) ($this->target?->errorCount($op) ?? 0),
            (string) ($this->freedsx?->errorCount($op) ?? 0),
        ];
    }

    /**
     * @return list<string>
     */
    private function unionOps(): array
    {
        $ops = array_merge(
            $this->target?->operations() ?? [],
            $this->freedsx?->operations() ?? [],
        );

        return array_values(array_unique($ops));
    }

    private function renderJson(): string
    {
        return json_encode(
            [
                'target' => $this->snapshotToArray($this->target),
                'freedsx' => $this->snapshotToArray($this->freedsx),
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
