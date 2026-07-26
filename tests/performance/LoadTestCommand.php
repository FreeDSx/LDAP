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

namespace Tests\Performance\FreeDSx\Ldap;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use InvalidArgumentException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Tests\Performance\FreeDSx\Ldap\Report\Report;
use Tests\Performance\FreeDSx\Ldap\Threshold\CiThresholds;
use Tests\Performance\FreeDSx\Ldap\Threshold\ThresholdEvaluator;
use Tests\Performance\FreeDSx\Ldap\Threshold\ThresholdResult;
use Tests\Performance\FreeDSx\Ldap\Threshold\ThresholdSet;
use Tests\Performance\FreeDSx\Ldap\Workload\WorkloadMix;
use Throwable;

/**
 * Symfony Console entry point that parses CLI options, builds a Config, and runs the Driver.
 */
final class LoadTestCommand extends Command
{
    protected static $defaultName = 'load-test';

    protected static $defaultDescription = 'Run a concurrent LDAP load test against a storage backend.';

    protected function configure(): void
    {
        $this
            ->addOption(
                'backend',
                null,
                InputOption::VALUE_REQUIRED,
                'Storage adapter: ' . implode(' | ', Config::BACKENDS),
            )
            ->addOption(
                'runner',
                null,
                InputOption::VALUE_REQUIRED,
                'Server runner: ' . implode(' | ', Config::RUNNERS) . ' (memory REQUIRES swoole)',
            )
            ->addOption(
                'swoole-workers',
                null,
                InputOption::VALUE_REQUIRED,
                'Swoole worker processes: 0 auto-detects the CPU count, 1 pins it to a single process',
                '0',
            )
            ->addOption(
                'clients',
                null,
                InputOption::VALUE_REQUIRED,
                'Concurrent coroutines',
                '16',
            )
            ->addOption(
                'duration',
                null,
                InputOption::VALUE_REQUIRED,
                'Seconds to run (default 10 unless --ops is set)',
            )
            ->addOption(
                'ops',
                null,
                InputOption::VALUE_REQUIRED,
                'Total ops per client (alternative to --duration)',
            )
            ->addOption(
                'mix',
                null,
                InputOption::VALUE_REQUIRED,
                'Op mix, comma-separated weights',
                Config::DEFAULT_MIX,
            )
            ->addOption(
                'host',
                null,
                InputOption::VALUE_REQUIRED,
                'Bind host',
                '127.0.0.1',
            )
            ->addOption(
                'port',
                null,
                InputOption::VALUE_REQUIRED,
                'Listen port',
                '10389',
            )
            ->addOption(
                'warmup',
                null,
                InputOption::VALUE_REQUIRED,
                'Warmup seconds before sampling',
                '2',
            )
            ->addOption(
                'server',
                null,
                InputOption::VALUE_REQUIRED,
                'spawn = script manages server; external = already running',
                'spawn',
            )
            ->addOption(
                'rng-seed',
                null,
                InputOption::VALUE_REQUIRED,
                'RNG seed for reproducible workloads',
            )
            ->addOption(
                'output',
                null,
                InputOption::VALUE_REQUIRED,
                'Report format: ' . implode(' | ', Config::OUTPUTS),
                'text',
            )
            ->addOption(
                'seed-entries',
                null,
                InputOption::VALUE_REQUIRED,
                'Extra fixture entries to pre-seed under ou=people before the run',
                '100',
            )
            ->addOption(
                'bind-dn',
                null,
                InputOption::VALUE_REQUIRED,
                'DN used to bind each worker client',
                Config::DEFAULT_BIND_DN,
            )
            ->addOption(
                'bind-password',
                null,
                InputOption::VALUE_REQUIRED,
                'Password paired with --bind-dn',
                Config::DEFAULT_BIND_PASSWORD,
            )
            ->addOption(
                'base-dn',
                null,
                InputOption::VALUE_REQUIRED,
                'Search base for read/eq/sub operations',
                Config::DEFAULT_BASE_DN,
            )
            ->addOption(
                'write-base',
                null,
                InputOption::VALUE_REQUIRED,
                'Parent DN for add/modify/delete + seed-N entries',
                Config::DEFAULT_WRITE_BASE,
            )
            ->addOption(
                'ci-profile',
                null,
                InputOption::VALUE_REQUIRED,
                'Apply built-in CI thresholds for combo: ' . implode(' | ', CiThresholds::KNOWN_PROFILES),
            )
            ->addOption(
                'max-error-rate',
                null,
                InputOption::VALUE_REQUIRED,
                'Fail if error rate exceeds this fraction (e.g. 0.001 = 0.1%); overrides --ci-profile',
            )
            ->addOption(
                'max-errors',
                null,
                InputOption::VALUE_REQUIRED,
                'Fail if total errors exceed this count; overrides --ci-profile',
            )
            ->addOption(
                'min-throughput',
                null,
                InputOption::VALUE_REQUIRED,
                'Fail if overall ops/sec falls below this floor; overrides --ci-profile',
            )
            ->addOption(
                'max-p99-ms',
                null,
                InputOption::VALUE_REQUIRED,
                'Fail if any op\'s p99 latency exceeds this ceiling (ms); overrides --ci-profile',
            )
            ->addOption(
                'threshold-report',
                null,
                InputOption::VALUE_REQUIRED,
                'Path to write per-gate pass/fail JSON report (for CI artifact upload)',
            )
            ->addOption(
                'no-jit',
                null,
                InputOption::VALUE_NONE,
                'Disable opcache + tracing JIT on the spawned FreeDSx server (default: enabled for swoole, off for pcntl).',
            )
            ->addOption(
                'monitor',
                null,
                InputOption::VALUE_NEGATABLE,
                'Print server-side cn=monitor counters after the run (on by default; use --no-monitor to disable).',
                true,
            )
            ->addOption(
                'search-size-limit',
                null,
                InputOption::VALUE_REQUIRED,
                'Per-request size limit applied to search-list and search-sub ops (0 = unlimited)',
                (string) Config::DEFAULT_SEARCH_SIZE_LIMIT,
            )
            ->addOption(
                'search-value',
                null,
                InputOption::VALUE_REQUIRED,
                'cn prefix the subtree searches filter on; a broader value (e.g. "seed-") matches more entries',
                Config::DEFAULT_SEARCH_VALUE,
            )
            ->addOption(
                'search-sort-size-limit',
                null,
                InputOption::VALUE_REQUIRED,
                'Per-request size limit applied to search-sort ops (0 = unlimited)',
                (string) Config::DEFAULT_SEARCH_SORT_SIZE_LIMIT,
            )
            ->addOption(
                'search-attributes',
                null,
                InputOption::VALUE_REQUIRED,
                'Attributes requested by search ops: a CSV list, ALL (default), or 1.1 for no attributes.',
            )
            ->addOption(
                'attributes-only',
                null,
                InputOption::VALUE_NONE,
                'Request attribute descriptions without values (attributesOnly) on search ops.',
            )
            ->addOption(
                'seed-attributes',
                null,
                InputOption::VALUE_REQUIRED,
                'Filler attributes added to each seeded entry to widen the return path (0 = none).',
                '0',
            )
            ->addOption(
                'max-search-lookthrough',
                null,
                InputOption::VALUE_REQUIRED,
                'Max entries examined per search before adminLimitExceeded (0 = unbounded; default mirrors the server).',
                (string) Config::DEFAULT_MAX_SEARCH_LOOKTHROUGH,
            )
            ->addOption(
                'journal',
                null,
                InputOption::VALUE_NONE,
                'Enable the change journal on the spawned server so every write appends a change record.',
            );
    }

    protected function execute(
        InputInterface $input,
        OutputInterface $output,
    ): int {
        $errorOutput = $output instanceof ConsoleOutputInterface
            ? $output->getErrorOutput()
            : $output;

        try {
            $config = $this->buildConfig($input);
            $thresholds = $this->buildThresholds($input);
        } catch (InvalidArgumentException $e) {
            $errorOutput->writeln('<error>Configuration error: ' . $e->getMessage() . '</error>');

            return Command::INVALID;
        }

        $monitorEntry = null;
        $afterRun = $config->monitor
            ? function () use ($config, &$monitorEntry, $errorOutput): void {
                $monitorEntry = $this->readMonitorEntry($config, $errorOutput);
            }
        : null;

        try {
            $snapshot = (new Driver($config))->run(
                $output,
                $afterRun,
            );
        } catch (Throwable $e) {
            $errorOutput->writeln('<error>Load test failed: ' . $e->getMessage() . '</error>');

            return Command::FAILURE;
        }

        $mix = new WorkloadMix($config->mix);
        (new Report($config, $mix, $snapshot))->render($output);

        if ($monitorEntry !== null) {
            $this->renderMonitorEntry(
                $output,
                $monitorEntry,
            );
        }

        if ($thresholds->isEmpty()) {
            return Command::SUCCESS;
        }

        $result = (new ThresholdEvaluator())->evaluate($snapshot, $thresholds);

        $reportPath = $input->getOption('threshold-report');
        if (is_string($reportPath) && $reportPath !== '') {
            $this->writeThresholdReport(
                $reportPath,
                $result,
            );
        }

        if ($result->passed) {
            return Command::SUCCESS;
        }

        $this->renderThresholdFailure(
            $errorOutput,
            $result,
        );

        return Command::FAILURE;
    }

    /**
     * Read the cn=monitor entry from the still-running server for cross-checking against the load-test totals.
     *
     * @return array<string, list<string>>|null
     */
    private function readMonitorEntry(
        Config $config,
        OutputInterface $errorOutput,
    ): ?array {
        // Let the forking parent reap the just-closed worker connections and fold their final deltas first.
        usleep(500_000);

        try {
            $client = new LdapClient(
                (new ClientOptions())
                    ->setServers([$config->host])
                    ->setPort($config->port),
            );
            $client->bind(
                $config->bindDn,
                $config->bindPassword,
            );
            $entries = $client->search(
                Operations::search(Filters::present('objectClass'))
                    ->base('cn=monitor')
                    ->useBaseScope(),
            );
            $client->unbind();
        } catch (Throwable $e) {
            $errorOutput->writeln('<comment>Could not read cn=monitor: ' . $e->getMessage() . '</comment>');

            return null;
        }

        foreach ($entries as $entry) {
            $values = [];
            foreach ($entry->getAttributes() as $attribute) {
                $values[$attribute->getName()] = array_values($attribute->getValues());
            }

            return $values;
        }

        return null;
    }

    /**
     * @param array<string, list<string>> $entry
     */
    private function renderMonitorEntry(
        OutputInterface $output,
        array $entry,
    ): void {
        $output->writeln('');
        $output->writeln(
            'cn=monitor (monotonic since start; includes warmup, per-connection binds/unbinds, and this query):',
        );

        $attributes = [
            'connectionsTotal',
            'connectionsActive',
            'operationsCompleted',
            'operationsFailed',
            'operationsByType',
            'operationsAvgLatencyMsByType',
            'operationsByResultCode',
            'bindsByMethod',
            'searchesByScope',
            'operationsInProgressByType',
            'trafficBytesSent',
            'trafficBytesReceived',
            'trafficEntriesReturned',
        ];

        $table = new Table($output);
        $table->setHeaders([
            'Stat',
            'Value',
        ]);
        foreach ($attributes as $name) {
            if (!isset($entry[$name])) {
                continue;
            }

            // Multi-valued stats (per-op counts/latencies) read better one pair per line in the cell.
            $table->addRow([
                $name,
                implode("\n", $entry[$name]),
            ]);
        }
        $table->render();
    }

    private function buildConfig(InputInterface $input): Config
    {
        $backend = $this->requireString($input, 'backend');
        $runner = $this->requireString($input, 'runner');

        $opsOpt = $input->getOption('ops');
        $durationOpt = $input->getOption('duration');
        $ops = $this->parseInt($opsOpt, 'ops');

        if ($durationOpt !== null) {
            $duration = $this->parseInt($durationOpt, 'duration');
        } elseif ($ops !== null) {
            $duration = null;
        } else {
            $duration = 10;
        }

        return new Config(
            backend: $backend,
            runner: $runner,
            clients: $this->requireInt($input, 'clients'),
            duration: $duration,
            ops: $ops,
            mix: $this->requireString($input, 'mix'),
            host: $this->requireString($input, 'host'),
            port: $this->requireInt($input, 'port'),
            warmup: $this->requireInt($input, 'warmup'),
            serverMode: $this->requireString($input, 'server'),
            rngSeed: $this->parseInt($input->getOption('rng-seed'), 'rng-seed'),
            output: $this->requireString($input, 'output'),
            seedEntries: $this->requireInt($input, 'seed-entries'),
            bindDn: $this->requireString($input, 'bind-dn'),
            bindPassword: $this->requireString($input, 'bind-password'),
            baseDn: $this->requireString($input, 'base-dn'),
            writeBase: $this->requireString($input, 'write-base'),
            // The spawned server defaults JIT off for pcntl (tracing JIT can crash forked workers under load)
            // Swoole keeps it. --no-jit forces it off either way.
            jit: !(bool) $input->getOption('no-jit') && $runner !== 'pcntl',
            searchSizeLimit: $this->requireInt($input, 'search-size-limit'),
            searchValue: $this->requireString($input, 'search-value'),
            searchSortSizeLimit: $this->requireInt($input, 'search-sort-size-limit'),
            monitor: (bool) $input->getOption('monitor'),
            searchAttributes: $this->optionalString($input, 'search-attributes'),
            attributesOnly: (bool) $input->getOption('attributes-only'),
            seedAttributes: $this->requireInt($input, 'seed-attributes'),
            maxSearchLookthrough: $this->requireInt($input, 'max-search-lookthrough'),
            journal: (bool) $input->getOption('journal'),
            swooleWorkers: $this->requireInt($input, 'swoole-workers'),
        );
    }

    private function optionalString(InputInterface $input, string $name): ?string
    {
        $value = $input->getOption($name);

        return is_string($value) && $value !== ''
            ? $value
            : null;
    }

    private function requireString(InputInterface $input, string $name): string
    {
        $value = $input->getOption($name);

        if (!is_string($value) || $value === '') {
            throw new InvalidArgumentException("--{$name} is required.");
        }

        return $value;
    }

    private function requireInt(InputInterface $input, string $name): int
    {
        $value = $this->parseInt($input->getOption($name), $name);

        if ($value === null) {
            throw new InvalidArgumentException("--{$name} is required.");
        }

        return $value;
    }

    private function parseInt(mixed $value, string $name): ?int
    {
        if ($value === null) {
            return null;
        }

        if (!is_string($value) || !preg_match('/^-?\d+$/', $value)) {
            $display = is_scalar($value)
                ? (string) $value
                : get_debug_type($value);

            throw new InvalidArgumentException("--{$name} must be an integer, got \"{$display}\".");
        }

        return (int) $value;
    }

    private function parseFloat(mixed $value, string $name): ?float
    {
        if ($value === null) {
            return null;
        }

        if (!is_string($value) || !preg_match('/^-?\d+(\.\d+)?$/', $value)) {
            $display = is_scalar($value)
                ? (string) $value
                : get_debug_type($value);

            throw new InvalidArgumentException("--{$name} must be a number, got \"{$display}\".");
        }

        return (float) $value;
    }

    private function buildThresholds(InputInterface $input): ThresholdSet
    {
        $profile = $input->getOption('ci-profile');
        $base = is_string($profile) && $profile !== ''
            ? CiThresholds::forProfile($profile)
            : new ThresholdSet();

        $overrides = new ThresholdSet(
            maxErrorRate: $this->parseFloat($input->getOption('max-error-rate'), 'max-error-rate'),
            maxErrors: $this->parseInt($input->getOption('max-errors'), 'max-errors'),
            minThroughput: $this->parseFloat($input->getOption('min-throughput'), 'min-throughput'),
            maxP99Ms: $this->parseFloat($input->getOption('max-p99-ms'), 'max-p99-ms'),
        );

        return $base->withOverrides($overrides);
    }

    private function writeThresholdReport(
        string $path,
        ThresholdResult $result,
    ): void {
        $payload = [
            'passed' => $result->passed,
            'gates' => $result->gates,
        ];

        file_put_contents(
            $path,
            json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
        );
    }

    private function renderThresholdFailure(
        OutputInterface $output,
        ThresholdResult $result,
    ): void {
        $output->writeln('');
        $output->writeln('<error>Threshold check failed:</error>');

        foreach ($result->failedGates() as $gate) {
            $output->writeln(sprintf(
                '  - %s: expected %s, got %s',
                $gate['gate'],
                $gate['expected'],
                $gate['actual'],
            ));
        }
    }
}
