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

namespace Tests\Performance\FreeDSx\Ldap\Report;

use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Output\OutputInterface;
use Tests\Performance\FreeDSx\Ldap\Config;
use Tests\Performance\FreeDSx\Ldap\Stats\StatsSnapshot;
use Tests\Performance\FreeDSx\Ldap\Workload\WorkloadMix;

/**
 * Formats a StatsSnapshot as either a human-readable table or machine-readable JSON.
 */
final class Report
{
    private const HEADERS = [
        'Operation',
        'Count',
        'Errors',
        'Ops/sec',
        'Min',
        'p50',
        'p95',
        'p99',
        'Max',
        'Mean',
    ];

    public function __construct(
        private readonly Config $config,
        private readonly WorkloadMix $mix,
        private readonly StatsSnapshot $snapshot,
    ) {
    }

    public function render(OutputInterface $output): void
    {
        if ($this->config->output === 'json') {
            $output->writeln($this->renderJson());

            return;
        }

        $this->renderText($output);
    }

    private function renderText(OutputInterface $output): void
    {
        $output->writeln($this->renderBanner());
        $output->writeln('');

        $table = new Table($output);
        $table->setHeaders(self::HEADERS);
        foreach ($this->snapshot->operations() as $op) {
            $table->addRow($this->textRow($op));
        }
        $table->render();

        $output->writeln('');
        $output->writeln($this->renderTotals());

        $substitutions = $this->renderSubstitutions();
        if ($substitutions !== '') {
            $output->writeln($substitutions);
        }
    }

    /**
     * @return list<string>
     */
    private function textRow(string $op): array
    {
        $stats = $this->snapshot->latencyStats($op);

        return [
            $op,
            (string) $this->snapshot->successCount($op),
            (string) $this->snapshot->errorCount($op),
            number_format($this->snapshot->throughput($op), 2),
            self::formatNanos($stats['min']),
            self::formatNanos($stats['p50']),
            self::formatNanos($stats['p95']),
            self::formatNanos($stats['p99']),
            self::formatNanos($stats['max']),
            self::formatNanos($stats['mean']),
        ];
    }

    private function renderBanner(): string
    {
        $duration = $this->config->duration !== null
            ? sprintf('%ds', $this->config->duration)
            : sprintf('%d ops/client', $this->config->ops);

        $lines = [
            'FreeDSx LDAP load test',
            '======================',
            sprintf(
                'Backend: %s (%s runner)   Clients: %d   Duration: %s   Warmup: %ds   Elapsed: %.1fs',
                $this->config->backend,
                $this->config->runner,
                $this->config->clients,
                $duration,
                $this->config->warmup,
                $this->snapshot->elapsedSeconds,
            ),
            sprintf(
                'Mix: %s',
                $this->mix->describe(),
            ),
        ];

        return implode(PHP_EOL, $lines);
    }

    private function renderTotals(): string
    {
        $total = $this->snapshot->totalSuccess();
        $errors = $this->snapshot->totalErrors();
        $attempted = $total + $errors;
        $errPct = $attempted > 0 ? ($errors / $attempted) * 100 : 0.0;

        $line = sprintf(
            'Total: %d ops in %.1fs  |  Throughput: %s ops/sec  |  Errors: %d (%.3f%%)',
            $total,
            $this->snapshot->elapsedSeconds,
            number_format($this->snapshot->overallThroughput(), 1),
            $errors,
            $errPct,
        );

        $topErrs = $this->snapshot->topErrorClasses();
        if ($topErrs === []) {
            return $line;
        }

        $parts = [];
        foreach ($topErrs as $err) {
            $short = self::shortClass($err['class']);
            $parts[] = "{$short} ({$err['count']})";
        }

        return $line . PHP_EOL . 'Top errors: ' . implode(', ', $parts);
    }

    private function renderSubstitutions(): string
    {
        if ($this->snapshot->substituted === []) {
            return '';
        }

        $parts = [];
        foreach ($this->snapshot->substituted as $pair => $count) {
            $parts[] = "{$pair} ({$count})";
        }

        return 'Substituted (write op converted when worker had no owned DNs): ' . implode(', ', $parts);
    }

    private function renderJson(): string
    {
        $ops = [];
        foreach ($this->snapshot->operations() as $op) {
            $stats = $this->snapshot->latencyStats($op);
            $ops[$op] = [
                'count' => $this->snapshot->successCount($op),
                'errors' => $this->snapshot->errorCount($op),
                'throughput' => $this->snapshot->throughput($op),
                'latency_ns' => $stats,
            ];
        }

        return json_encode([
            'config' => [
                'backend' => $this->config->backend,
                'runner' => $this->config->runner,
                'clients' => $this->config->clients,
                'duration' => $this->config->duration,
                'ops' => $this->config->ops,
                'warmup' => $this->config->warmup,
                'mix' => $this->mix->weights(),
                'host' => $this->config->host,
                'port' => $this->config->port,
            ],
            'elapsed_seconds' => $this->snapshot->elapsedSeconds,
            'operations' => $ops,
            'totals' => [
                'success' => $this->snapshot->totalSuccess(),
                'errors' => $this->snapshot->totalErrors(),
                'throughput' => $this->snapshot->overallThroughput(),
            ],
            'top_error_classes' => $this->snapshot->topErrorClasses(),
            'substituted' => $this->snapshot->substituted,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    private static function formatNanos(int $nanos): string
    {
        if ($nanos === 0) {
            return '-';
        }

        return sprintf('%.2fms', $nanos / 1_000_000);
    }

    private static function shortClass(string $fqcn): string
    {
        $pos = strrpos($fqcn, '\\');

        return $pos === false ? $fqcn : substr($fqcn, $pos + 1);
    }
}
