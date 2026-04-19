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

namespace Tests\Performance\FreeDSx\Ldap\LoadTest;

use InvalidArgumentException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
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
                'seed',
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
            );
    }

    protected function execute(
        InputInterface $input,
        OutputInterface $output,
    ): int {
        try {
            $config = $this->buildConfig($input);
        } catch (InvalidArgumentException $e) {
            $output->writeln('<error>Configuration error: ' . $e->getMessage() . '</error>');

            return Command::INVALID;
        }

        try {
            (new Driver($config))->run($output);
        } catch (Throwable $e) {
            $output->writeln('<error>Load test failed: ' . $e->getMessage() . '</error>');

            return Command::FAILURE;
        }

        return Command::SUCCESS;
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
            seed: $this->parseInt($input->getOption('seed'), 'seed'),
            output: $this->requireString($input, 'output'),
            seedEntries: $this->requireInt($input, 'seed-entries'),
        );
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
}
