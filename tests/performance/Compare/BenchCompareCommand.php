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

/**
 * Runs the load test against an external LDAP target and FreeDSx (spawned) with
 * identical workload parameters, then prints a side-by-side comparison. Target defaults
 * assume a local OpenLDAP; override `--target-*` to point at another server (389 DS,
 * OpenDJ, ApacheDS, etc). Active Directory is not supported — the seeder uses
 * `inetOrgPerson + extensibleObject`.
 */
final class BenchCompareCommand extends Command
{
    protected static $defaultName = 'load-compare';

    protected static $defaultDescription = 'Benchmark FreeDSx vs an external LDAP target under identical workload parameters.';

    private const DEFAULT_TARGET_BASE_DN = 'dc=example,dc=com';

    private const DEFAULT_TARGET_BIND_DN = 'cn=admin,dc=example,dc=com';

    private const DEFAULT_TARGET_BIND_PASSWORD = 'P@ssword12345';

    private const DEFAULT_FREEDSX_PORT = 10389;

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
                'Fixture entries to pre-seed under the write base',
                '5000',
            )
            ->addOption(
                'rng-seed',
                null,
                InputOption::VALUE_REQUIRED,
                'RNG seed for reproducible workloads (applied to both runs)',
            )
            ->addOption(
                'freedsx-backend',
                null,
                InputOption::VALUE_REQUIRED,
                'FreeDSx backend: ' . implode(' | ', Config::BACKENDS),
                'sqlite',
            )
            ->addOption(
                'freedsx-runner',
                null,
                InputOption::VALUE_REQUIRED,
                'FreeDSx runner: ' . implode(' | ', Config::RUNNERS),
                'swoole',
            )
            ->addOption(
                'freedsx-port',
                null,
                InputOption::VALUE_REQUIRED,
                'Port to spawn FreeDSx on',
                (string) self::DEFAULT_FREEDSX_PORT,
            )
            ->addOption(
                'target-host',
                null,
                InputOption::VALUE_REQUIRED,
                'External LDAP target host',
                '127.0.0.1',
            )
            ->addOption(
                'target-port',
                null,
                InputOption::VALUE_REQUIRED,
                'External LDAP target port',
                '389',
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
                'skip-target',
                null,
                InputOption::VALUE_NONE,
                'Skip the target run (FreeDSx-only)',
            )
            ->addOption(
                'skip-freedsx',
                null,
                InputOption::VALUE_NONE,
                'Skip the FreeDSx run (target-only)',
            )
            ->addOption(
                'no-cleanup',
                null,
                InputOption::VALUE_NONE,
                'Leave the target bench subtree in place after the run',
            )
            ->addOption(
                'output',
                null,
                InputOption::VALUE_REQUIRED,
                'Report format: ' . implode(' | ', Config::OUTPUTS),
                'text',
            );
    }

    protected function execute(
        InputInterface $input,
        OutputInterface $output,
    ): int {
        $progress = $this->progressChannel($output);
        $skipTarget = (bool) $input->getOption('skip-target');
        $skipFreedsx = (bool) $input->getOption('skip-freedsx');

        if ($skipTarget && $skipFreedsx) {
            $output->writeln('<error>Both --skip-target and --skip-freedsx are set; nothing to run.</error>');

            return Command::INVALID;
        }

        try {
            $params = $this->resolveParams($input);
        } catch (InvalidArgumentException $e) {
            $output->writeln('<error>Configuration error: ' . $e->getMessage() . '</error>');

            return Command::INVALID;
        }

        $targetSnapshot = null;
        $freedsxSnapshot = null;

        $bench = $skipTarget
            ? null
            : $this->makeBench($input);

        try {
            if ($bench !== null) {
                $this->seedTarget(
                    $progress,
                    $bench,
                    $params['seedEntries'],
                );

                $targetSnapshot = $this->runAgainstTarget(
                    $output,
                    $progress,
                    $input,
                    $bench,
                    $params,
                );
                $this->renderSingleRun(
                    $output,
                    'Target',
                    $targetSnapshot,
                    $this->buildTargetConfig(
                        $input,
                        $bench,
                        $params,
                    ),
                );
            }

            if (!$skipFreedsx) {
                $freedsxSnapshot = $this->runAgainstFreedsx(
                    $output,
                    $progress,
                    $input,
                    $params,
                );
                $this->renderSingleRun(
                    $output,
                    'FreeDSx',
                    $freedsxSnapshot,
                    $this->buildFreedsxConfig(
                        $input,
                        $params,
                    ),
                );
            }
        } catch (Throwable $e) {
            $output->writeln('<error>Benchmark failed: ' . $e->getMessage() . '</error>');

            return Command::FAILURE;
        } finally {
            if ($bench !== null) {
                if (!$input->getOption('no-cleanup')) {
                    $progress->writeln(sprintf(
                        'Cleaning up target bench subtree at %s...',
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

        $format = $this->requireString($input, 'output');
        (new ComparisonReport(
            target: $targetSnapshot,
            freedsx: $freedsxSnapshot,
            format: $format,
        ))->render($output);

        return Command::SUCCESS;
    }

    /**
     * @return array{duration: ?int, ops: ?int, mix: string, clients: int, warmup: int, rngSeed: ?int, seedEntries: int}
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

        return [
            'duration' => $duration,
            'ops' => $ops,
            'mix' => $this->requireString($input, 'mix'),
            'clients' => $this->requireInt($input, 'clients'),
            'warmup' => $this->requireInt($input, 'warmup'),
            'rngSeed' => $this->parseInt($input->getOption('rng-seed'), 'rng-seed'),
            'seedEntries' => $this->requireInt($input, 'seed-entries'),
        ];
    }

    private function makeBench(InputInterface $input): TargetBench
    {
        return new TargetBench(
            host: $this->requireString($input, 'target-host'),
            port: $this->requireInt($input, 'target-port'),
            bindDn: $this->requireString($input, 'target-bind-dn'),
            bindPassword: $this->requireString($input, 'target-bind-password'),
            rootBaseDn: $this->requireString($input, 'target-base-dn'),
        );
    }

    private function seedTarget(
        OutputInterface $progress,
        TargetBench $bench,
        int $seedEntries,
    ): void {
        $progress->writeln(sprintf(
            'Seeding target bench subtree %s with %d entries (+ cn=alice)...',
            $bench->benchBaseDn,
            $seedEntries,
        ));

        $start = microtime(true);
        $bench->seed($seedEntries);
        $elapsed = microtime(true) - $start;

        $progress->writeln(sprintf(
            'Target seed complete in %.1fs.',
            $elapsed,
        ));
    }

    /**
     * @param array{duration: ?int, ops: ?int, mix: string, clients: int, warmup: int, rngSeed: ?int, seedEntries: int} $params
     */
    private function runAgainstTarget(
        OutputInterface $output,
        OutputInterface $progress,
        InputInterface $input,
        TargetBench $bench,
        array $params,
    ): StatsSnapshot {
        $progress->writeln('Running workload against target...');

        $config = $this->buildTargetConfig(
            $input,
            $bench,
            $params,
        );

        return (new Driver($config))->run($output);
    }

    /**
     * @param array{duration: ?int, ops: ?int, mix: string, clients: int, warmup: int, rngSeed: ?int, seedEntries: int} $params
     */
    private function runAgainstFreedsx(
        OutputInterface $output,
        OutputInterface $progress,
        InputInterface $input,
        array $params,
    ): StatsSnapshot {
        $progress->writeln('Running workload against FreeDSx...');

        $config = $this->buildFreedsxConfig(
            $input,
            $params,
        );

        return (new Driver($config))->run($output);
    }

    /**
     * @param array{duration: ?int, ops: ?int, mix: string, clients: int, warmup: int, rngSeed: ?int, seedEntries: int} $params
     */
    private function buildTargetConfig(
        InputInterface $input,
        TargetBench $bench,
        array $params,
    ): Config {
        return new Config(
            backend: $this->requireString($input, 'freedsx-backend'),
            runner: $this->requireString($input, 'freedsx-runner'),
            clients: $params['clients'],
            duration: $params['duration'],
            ops: $params['ops'],
            mix: $params['mix'],
            host: $this->requireString($input, 'target-host'),
            port: $this->requireInt($input, 'target-port'),
            warmup: $params['warmup'],
            serverMode: 'external',
            rngSeed: $params['rngSeed'],
            output: 'text',
            seedEntries: 0,
            bindDn: $this->requireString($input, 'target-bind-dn'),
            bindPassword: $this->requireString($input, 'target-bind-password'),
            baseDn: $bench->benchBaseDn,
            writeBase: $bench->writeBaseDn,
        );
    }

    /**
     * @param array{duration: ?int, ops: ?int, mix: string, clients: int, warmup: int, rngSeed: ?int, seedEntries: int} $params
     */
    private function buildFreedsxConfig(
        InputInterface $input,
        array $params,
    ): Config {
        return new Config(
            backend: $this->requireString($input, 'freedsx-backend'),
            runner: $this->requireString($input, 'freedsx-runner'),
            clients: $params['clients'],
            duration: $params['duration'],
            ops: $params['ops'],
            mix: $params['mix'],
            host: '127.0.0.1',
            port: $this->requireInt($input, 'freedsx-port'),
            warmup: $params['warmup'],
            serverMode: 'spawn',
            rngSeed: $params['rngSeed'],
            output: 'text',
            seedEntries: $params['seedEntries'],
        );
    }

    private function renderSingleRun(
        OutputInterface $output,
        string $label,
        StatsSnapshot $snapshot,
        Config $config,
    ): void {
        $output->writeln('');
        $output->writeln(sprintf('--- %s results ---', $label));
        (new Report(
            $config,
            new WorkloadMix($config->mix),
            $snapshot,
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
