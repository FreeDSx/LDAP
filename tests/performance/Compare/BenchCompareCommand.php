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

use InvalidArgumentException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Tests\Performance\FreeDSx\Ldap\Config;
use Tests\Performance\FreeDSx\Ldap\Driver;
use Tests\Performance\FreeDSx\Ldap\Report\Report;
use Tests\Performance\FreeDSx\Ldap\Stats\StatsSnapshot;
use Tests\Performance\FreeDSx\Ldap\Workload\WorkloadMix;
use Throwable;

final class BenchCompareCommand extends Command
{
    private const DEFAULT_SOURCE_LABEL = 'FreeDSx';

    private const DEFAULT_SOURCE_PORT = 10389;

    /**
     * The write mixes need an identity the harness treats as an administrator.
     */
    private const DEFAULT_SOURCE_BIND_DN = 'cn=admin,dc=foo,dc=bar';

    private const DEFAULT_SOURCE_BIND_PASSWORD = '12345';

    private const DEFAULT_SOURCE_BASE_DN = 'dc=foo,dc=bar';

    private const DEFAULT_TARGET_LABEL = 'Target';

    private const DEFAULT_TARGET_PORT = 10390;

    private const DEFAULT_TARGET_BIND_DN = 'cn=admin,dc=example,dc=com';

    private const DEFAULT_TARGET_BIND_PASSWORD = 'P@ssword12345';

    private const DEFAULT_TARGET_BASE_DN = 'dc=example,dc=com';

    protected static $defaultName = 'load-compare';

    protected static $defaultDescription = 'Benchmark a source LDAP server against a target under identical workload parameters.';

    protected function configure(): void
    {
        $this
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
                'Seconds per run (default 15 unless --ops is set)',
            )
            ->addOption(
                'ops',
                null,
                InputOption::VALUE_REQUIRED,
                'Total ops per client (alternative to --duration)',
            )
            ->addOption(
                'warmup',
                null,
                InputOption::VALUE_REQUIRED,
                'Warmup seconds before sampling',
                '3',
            )
            ->addOption(
                'mix',
                null,
                InputOption::VALUE_REQUIRED,
                'Op mix, comma-separated weights',
                'search-eq=100',
            )
            ->addOption(
                'seed-entries',
                null,
                InputOption::VALUE_REQUIRED,
                'Fixture entries to pre-seed under each side write base',
                '5000',
            )
            ->addOption(
                'rng-seed',
                null,
                InputOption::VALUE_REQUIRED,
                'RNG seed for reproducible workloads (applied to both runs)',
            )
            ->addOption(
                'source-host',
                null,
                InputOption::VALUE_REQUIRED,
                'Source server host',
                '127.0.0.1',
            )
            ->addOption(
                'source-port',
                null,
                InputOption::VALUE_REQUIRED,
                'Source server port',
                (string) self::DEFAULT_SOURCE_PORT,
            )
            ->addOption(
                'source-bind-dn',
                null,
                InputOption::VALUE_REQUIRED,
                'DN to bind to the source for seeding + workload',
                self::DEFAULT_SOURCE_BIND_DN,
            )
            ->addOption(
                'source-bind-password',
                null,
                InputOption::VALUE_REQUIRED,
                'Password paired with --source-bind-dn',
                self::DEFAULT_SOURCE_BIND_PASSWORD,
            )
            ->addOption(
                'source-base-dn',
                null,
                InputOption::VALUE_REQUIRED,
                'Source base DN below which the bench subtree is created',
                self::DEFAULT_SOURCE_BASE_DN,
            )
            ->addOption(
                'source-label',
                null,
                InputOption::VALUE_REQUIRED,
                'Display name for the source server in the report (the project under test)',
                self::DEFAULT_SOURCE_LABEL,
            )
            ->addOption(
                'target-host',
                null,
                InputOption::VALUE_REQUIRED,
                'Target server host',
                '127.0.0.1',
            )
            ->addOption(
                'target-port',
                null,
                InputOption::VALUE_REQUIRED,
                'Target server port (the bundled bench OpenLDAP publishes 10390; use 389 for a standard slapd)',
                (string) self::DEFAULT_TARGET_PORT,
            )
            ->addOption(
                'target-bind-dn',
                null,
                InputOption::VALUE_REQUIRED,
                'DN to bind to the target for seeding + workload',
                self::DEFAULT_TARGET_BIND_DN,
            )
            ->addOption(
                'target-bind-password',
                null,
                InputOption::VALUE_REQUIRED,
                'Password paired with --target-bind-dn',
                self::DEFAULT_TARGET_BIND_PASSWORD,
            )
            ->addOption(
                'target-base-dn',
                null,
                InputOption::VALUE_REQUIRED,
                'Target base DN below which the bench subtree is created',
                self::DEFAULT_TARGET_BASE_DN,
            )
            ->addOption(
                'target-label',
                null,
                InputOption::VALUE_REQUIRED,
                'Display name for the target server in the report (e.g. OpenLDAP)',
                self::DEFAULT_TARGET_LABEL,
            )
            ->addOption(
                'skip-target',
                null,
                InputOption::VALUE_NONE,
                'Skip the target run (source-only)',
            )
            ->addOption(
                'skip-source',
                null,
                InputOption::VALUE_NONE,
                'Skip the source run (target-only)',
            )
            ->addOption(
                'no-cleanup',
                null,
                InputOption::VALUE_NONE,
                'Leave the bench subtrees in place after the run',
            )
            ->addOption(
                'output',
                null,
                InputOption::VALUE_REQUIRED,
                'Report format: ' . implode(' | ', Config::OUTPUTS),
                'text',
            )
            ->addOption(
                'no-jit',
                null,
                InputOption::VALUE_NONE,
                'Disable opcache + tracing JIT on the multi-process driver workers (default: enabled).',
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
                'driver-processes',
                null,
                InputOption::VALUE_REQUIRED,
                'Number of OS-level driver processes to fan out (each runs --clients coroutines). '
                . 'Use >1 to escape the single-process bench client throughput ceiling.',
                '1',
            );
    }

    protected function execute(
        InputInterface $input,
        OutputInterface $output,
    ): int {
        $progress = $this->progressChannel($output);
        $skipTarget = (bool) $input->getOption('skip-target');
        $skipSource = (bool) $input->getOption('skip-source');

        if ($skipTarget && $skipSource) {
            $output->writeln('<error>Both --skip-target and --skip-source are set; nothing to run.</error>');

            return Command::INVALID;
        }

        try {
            $params = $this->resolveParams($input);
        } catch (InvalidArgumentException $e) {
            $output->writeln('<error>Configuration error: ' . $e->getMessage() . '</error>');

            return Command::INVALID;
        }

        $targetSide = $this->sideFromOptions($input, 'target');
        $sourceSide = $this->sideFromOptions($input, 'source');

        $targetSnapshot = null;
        $sourceSnapshot = null;
        $benches = [];

        try {
            if (!$skipTarget) {
                $targetSnapshot = $this->runSide($output, $progress, $targetSide, $params, $benches);
            }
            if (!$skipSource) {
                $sourceSnapshot = $this->runSide($output, $progress, $sourceSide, $params, $benches);
            }
        } catch (Throwable $e) {
            $output->writeln('<error>Benchmark failed: ' . $e->getMessage() . '</error>');

            return Command::FAILURE;
        } finally {
            $this->teardownBenches($progress, $benches, (bool) $input->getOption('no-cleanup'));
        }

        $format = $this->requireString($input, 'output');
        (new ComparisonReport(
            target: $targetSnapshot,
            source: $sourceSnapshot,
            format: $format,
            targetLabel: $targetSide->label,
            sourceLabel: $sourceSide->label,
        ))->render($output);

        return Command::SUCCESS;
    }

    /**
     * @param array{duration: ?int, ops: ?int, mix: string, clients: int, warmup: int, rngSeed: ?int, seedEntries: int, jit: bool, searchSizeLimit: int, searchValue: string, driverProcesses: int} $params
     * @param list<TargetBench> $benches
     */
    private function runSide(
        OutputInterface $output,
        OutputInterface $progress,
        BenchSide $side,
        array $params,
        array &$benches,
    ): StatsSnapshot {
        $bench = new TargetBench(
            host: $side->host,
            port: $side->port,
            bindDn: $side->bindDn,
            bindPassword: $side->bindPassword,
            rootBaseDn: $side->baseDn,
        );
        $benches[] = $bench;

        $this->seedSide(
            $progress,
            $side,
            $bench,
            $params['seedEntries'],
        );

        $config = $this->buildConfig(
            $side,
            $bench,
            $params,
        );

        $progress->writeln(sprintf(
            'Running workload against %s...',
            $side->label,
        ));

        $snapshot = $params['driverProcesses'] === 1
            ? (new Driver($config))->run($output)
            : (new MultiDriverCoordinator($params['driverProcesses']))->run(
                $config,
                $progress,
            );

        $this->renderSingleRun(
            $output,
            $side->label,
            $snapshot,
            $config,
            sprintf('%s load test', $side->label),
            true,
        );

        return $snapshot;
    }

    private function seedSide(
        OutputInterface $progress,
        BenchSide $side,
        TargetBench $bench,
        int $seedEntries,
    ): void {
        $progress->writeln(sprintf(
            'Seeding %s bench subtree %s with %d entries (+ cn=alice)...',
            $side->label,
            $bench->benchBaseDn,
            $seedEntries,
        ));

        $start = microtime(true);
        $bench->seed($seedEntries);
        $elapsed = microtime(true) - $start;

        $progress->writeln(sprintf(
            '%s seed complete in %.1fs.',
            $side->label,
            $elapsed,
        ));
    }

    /**
     * @param array{duration: ?int, ops: ?int, mix: string, clients: int, warmup: int, rngSeed: ?int, seedEntries: int, jit: bool, searchSizeLimit: int, searchValue: string, driverProcesses: int} $params
     */
    private function buildConfig(
        BenchSide $side,
        TargetBench $bench,
        array $params,
    ): Config {
        return new Config(
            // Backend/runner are FreeDSx-internal knobs; the driver only connects to host:port, so external runs pass
            // innocuous placeholders that satisfy Config validation without affecting the workload.
            backend: 'sqlite',
            runner: 'pcntl',
            clients: $params['clients'],
            duration: $params['duration'],
            ops: $params['ops'],
            mix: $params['mix'],
            host: $side->host,
            port: $side->port,
            warmup: $params['warmup'],
            serverMode: 'external',
            rngSeed: $params['rngSeed'],
            output: 'text',
            seedEntries: 0,
            bindDn: $side->bindDn,
            bindPassword: $side->bindPassword,
            baseDn: $bench->benchBaseDn,
            writeBase: $bench->writeBaseDn,
            jit: $params['jit'],
            searchSizeLimit: $params['searchSizeLimit'],
            searchValue: $params['searchValue'],
        );
    }

    /**
     * @param list<TargetBench> $benches
     */
    private function teardownBenches(
        OutputInterface $progress,
        array $benches,
        bool $noCleanup,
    ): void {
        foreach ($benches as $bench) {
            if (!$noCleanup) {
                $progress->writeln(sprintf(
                    'Cleaning up bench subtree at %s...',
                    $bench->benchBaseDn,
                ));
                try {
                    $bench->cleanup();
                } catch (Throwable $e) {
                    $progress->writeln('<comment>Cleanup warning: ' . $e->getMessage() . '</comment>');
                }
            }
            $bench->close();
        }
    }

    private function sideFromOptions(
        InputInterface $input,
        string $prefix,
    ): BenchSide {
        return new BenchSide(
            label: $this->requireString($input, "{$prefix}-label"),
            host: $this->requireString($input, "{$prefix}-host"),
            port: $this->requireInt($input, "{$prefix}-port"),
            bindDn: $this->requireString($input, "{$prefix}-bind-dn"),
            bindPassword: $this->requireString($input, "{$prefix}-bind-password"),
            baseDn: $this->requireString($input, "{$prefix}-base-dn"),
        );
    }

    /**
     * @return array{duration: ?int, ops: ?int, mix: string, clients: int, warmup: int, rngSeed: ?int, seedEntries: int, jit: bool, searchSizeLimit: int, searchValue: string, driverProcesses: int}
     */
    private function resolveParams(InputInterface $input): array
    {
        $opsOpt = $input->getOption('ops');
        $durationOpt = $input->getOption('duration');
        $ops = $this->parseInt($opsOpt, 'ops');

        if ($durationOpt !== null) {
            $duration = $this->parseInt($durationOpt, 'duration');
        } elseif ($ops !== null) {
            $duration = null;
        } else {
            $duration = 15;
        }

        $driverProcesses = $this->requireInt($input, 'driver-processes');
        if ($driverProcesses < 1) {
            throw new InvalidArgumentException('--driver-processes must be >= 1.');
        }

        return [
            'duration' => $duration,
            'ops' => $ops,
            'mix' => $this->requireString($input, 'mix'),
            'clients' => $this->requireInt($input, 'clients'),
            'warmup' => $this->requireInt($input, 'warmup'),
            'rngSeed' => $this->parseInt($input->getOption('rng-seed'), 'rng-seed'),
            'seedEntries' => $this->requireInt($input, 'seed-entries'),
            'jit' => !(bool) $input->getOption('no-jit'),
            'searchSizeLimit' => $this->requireInt($input, 'search-size-limit'),
            'searchValue' => $this->requireString($input, 'search-value'),
            'driverProcesses' => $driverProcesses,
        ];
    }

    private function renderSingleRun(
        OutputInterface $output,
        string $label,
        StatsSnapshot $snapshot,
        Config $config,
        ?string $subject = null,
        bool $external = false,
    ): void {
        $output->writeln('');
        $output->writeln(sprintf('--- %s results ---', $label));
        (new Report(
            $config,
            new WorkloadMix($config->mix),
            $snapshot,
            $subject,
            $external,
        ))->render($output);
    }

    private function progressChannel(OutputInterface $output): OutputInterface
    {
        if ($output instanceof ConsoleOutputInterface) {
            return $output->getErrorOutput();
        }

        return $output;
    }

    private function requireString(
        InputInterface $input,
        string $name,
    ): string {
        $value = $input->getOption($name);

        if (!is_string($value) || $value === '') {
            throw new InvalidArgumentException("--{$name} is required.");
        }

        return $value;
    }

    private function requireInt(
        InputInterface $input,
        string $name,
    ): int {
        $value = $this->parseInt($input->getOption($name), $name);

        if ($value === null) {
            throw new InvalidArgumentException("--{$name} is required.");
        }

        return $value;
    }

    private function parseInt(
        mixed $value,
        string $name,
    ): ?int {
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
}
