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

use RuntimeException;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Process\Process;
use Tests\Performance\FreeDSx\Ldap\Config;
use Tests\Performance\FreeDSx\Ldap\Stats\StatsSnapshot;
use Throwable;

/**
 * Fans out N OS-level Driver processes against an already-running server, then merges their per-process StatsSnapshot results into one aggregate snapshot.
 */
final class MultiDriverCoordinator
{
    private const WORKER_PATH = __DIR__ . '/../../bin/internals/bench_driver_worker.php';

    public function __construct(
        private readonly int $processes,
    ) {
        if ($this->processes < 1) {
            throw new RuntimeException(sprintf(
                'MultiDriverCoordinator requires processes >= 1, got %d.',
                $this->processes,
            ));
        }
    }

    public function run(
        Config $childConfig,
        OutputInterface $progress,
    ): StatsSnapshot {
        if ($childConfig->serverMode !== 'external') {
            throw new RuntimeException(
                'MultiDriverCoordinator requires the child config to use serverMode=external; '
                . 'the parent must own the server lifecycle.',
            );
        }

        $progress->writeln(sprintf(
            'Spawning %d driver processes...',
            $this->processes,
        ));

        $processes = $this->startChildren($childConfig);
        $snapshots = $this->collectSnapshots($processes, $progress);

        return $this->merge($snapshots);
    }

    /**
     * @return array<int, Process>
     */
    private function startChildren(Config $childConfig): array
    {
        $processes = [];

        for ($i = 0; $i < $this->processes; $i++) {
            $processes[$i] = $this->startChild(
                $this->configForChild($childConfig, $i),
            );
        }

        return $processes;
    }

    private function startChild(Config $config): Process
    {
        $command = [PHP_BINARY];
        if ($config->jit) {
            $command[] = '-dopcache.enable_cli=1';
            $command[] = '-dopcache.jit_buffer_size=128M';
            $command[] = '-dopcache.jit=tracing';
        }
        $command[] = self::WORKER_PATH;
        if (!$config->jit) {
            $command[] = '--no-jit';
        }

        $process = new Process($command);
        $process->setTimeout(null);
        $process->setInput(serialize($config));
        $process->start();

        return $process;
    }

    /**
     * @param array<int, Process> $processes
     * @return list<StatsSnapshot>
     */
    private function collectSnapshots(
        array $processes,
        OutputInterface $progress,
    ): array {
        $snapshots = [];
        $failures = [];

        foreach ($processes as $idx => $process) {
            $exitCode = $process->wait();

            if ($exitCode !== 0) {
                $failures[] = sprintf(
                    "child %d exited %d; stderr:\n%s",
                    $idx,
                    $exitCode,
                    trim($process->getErrorOutput()),
                );

                continue;
            }

            try {
                $snapshots[] = $this->decodeSnapshot($process->getOutput());
            } catch (Throwable $e) {
                $failures[] = sprintf(
                    "child %d snapshot decode failed: %s; stderr:\n%s",
                    $idx,
                    $e->getMessage(),
                    trim($process->getErrorOutput()),
                );
            }
        }

        if ($failures !== []) {
            throw new RuntimeException(
                "Multi-driver run had failures:\n" . implode("\n---\n", $failures),
            );
        }

        $progress->writeln(sprintf(
            'All %d driver processes completed.',
            count($snapshots),
        ));

        return $snapshots;
    }

    private function decodeSnapshot(string $stdout): StatsSnapshot
    {
        $payload = trim($stdout);

        if ($payload === '') {
            throw new RuntimeException('child produced empty stdout');
        }

        $snapshot = @unserialize($payload, [
            'allowed_classes' => [StatsSnapshot::class],
        ]);

        if (!$snapshot instanceof StatsSnapshot) {
            throw new RuntimeException('child stdout did not unserialize to a StatsSnapshot');
        }

        return $snapshot;
    }

    /**
     * Derives a per-child Config. RNG seed is offset per child so reproducibility is
     * preserved while children don't all hammer the same DNs in lockstep.
     */
    private function configForChild(Config $base, int $childIndex): Config
    {
        $seed = $base->rngSeed !== null
            ? $base->rngSeed + $childIndex
            : null;

        return new Config(
            backend: $base->backend,
            runner: $base->runner,
            clients: $base->clients,
            duration: $base->duration,
            ops: $base->ops,
            mix: $base->mix,
            host: $base->host,
            port: $base->port,
            warmup: $base->warmup,
            serverMode: $base->serverMode,
            rngSeed: $seed,
            output: $base->output,
            seedEntries: $base->seedEntries,
            bindDn: $base->bindDn,
            bindPassword: $base->bindPassword,
            baseDn: $base->baseDn,
            writeBase: $base->writeBase,
            jit: $base->jit,
            searchSubSizeLimit: $base->searchSubSizeLimit,
        );
    }

    /**
     * @param list<StatsSnapshot> $snapshots
     */
    private function merge(array $snapshots): StatsSnapshot
    {
        if ($snapshots === []) {
            throw new RuntimeException('Cannot merge zero snapshots.');
        }

        $samples = [];
        $counts = [];
        $errors = [];
        $errorClasses = [];
        $substituted = [];
        $elapsedMax = 0.0;

        foreach ($snapshots as $snap) {
            foreach ($snap->samples as $op => $opSamples) {
                if (!isset($samples[$op])) {
                    $samples[$op] = $opSamples;

                    continue;
                }
                foreach ($opSamples as $sample) {
                    $samples[$op][] = $sample;
                }
            }
            foreach ($snap->counts as $op => $count) {
                $counts[$op] = ($counts[$op] ?? 0) + $count;
            }
            foreach ($snap->errors as $op => $count) {
                $errors[$op] = ($errors[$op] ?? 0) + $count;
            }
            foreach ($snap->errorClasses as $op => $classes) {
                foreach ($classes as $class => $count) {
                    $errorClasses[$op][$class] = ($errorClasses[$op][$class] ?? 0) + $count;
                }
            }
            foreach ($snap->substituted as $key => $count) {
                $substituted[$key] = ($substituted[$key] ?? 0) + $count;
            }
            if ($snap->elapsedSeconds > $elapsedMax) {
                $elapsedMax = $snap->elapsedSeconds;
            }
        }

        return new StatsSnapshot(
            samples: $samples,
            counts: $counts,
            errors: $errors,
            errorClasses: $errorClasses,
            substituted: $substituted,
            elapsedSeconds: $elapsedMax,
        );
    }
}
