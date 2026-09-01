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

use RuntimeException;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Tests\Performance\FreeDSx\Ldap\Server\ServerManager;
use Tests\Performance\FreeDSx\Ldap\Stats\StatsCollector;
use Tests\Performance\FreeDSx\Ldap\Stats\StatsSnapshot;
use Tests\Performance\FreeDSx\Ldap\Workload\Worker;
use Tests\Performance\FreeDSx\Ldap\Workload\WorkloadMix;
use Throwable;

/**
 * Orchestrates a load-test run end-to-end: server lifecycle, forked client pool, barrier + deadline
 * coordination, cross-process stats merge, then a rendered report.
 */
final class Driver
{
    private const MAX_DIAGNOSTIC_BYTES = 4_000;

    public function __construct(
        private readonly Config $config,
    ) {}

    /**
     * @param (callable(): void)|null $afterRun Invoked once the run completes but before the server is torn down.
     */
    public function run(
        OutputInterface $output,
        ?callable $afterRun = null,
    ): StatsSnapshot {
        $this->assertPcntlAvailable();

        $progress = $this->progressChannel($output);
        $mix = new WorkloadMix($this->config->mix);
        $serverManager = $this->config->serverMode === 'spawn'
            ? new ServerManager($this->config)
            : null;

        if ($serverManager !== null) {
            $progress->writeln($this->describeServerStart());
            $serverManager->start();
            $progress->writeln('Server ready.');
        } else {
            $progress->writeln(sprintf(
                'Using external server at %s:%d.',
                $this->config->host,
                $this->config->port,
            ));
        }

        $progress->writeln($this->describeRunStart());

        try {
            $snapshot = $this->runForkPool($mix);
            // While the server is still up, let the caller read cn=monitor for an apples-to-apples cross-check.
            if ($afterRun !== null) {
                $afterRun();
            }

            return $snapshot;
        } finally {
            $this->reportServerDiagnostics($progress, $serverManager);
            $serverManager?->stop();
        }
    }

    /**
     * A warning the server logs mid-run says nothing to the client, so it has to be read off the process itself.
     */
    private function reportServerDiagnostics(
        OutputInterface $progress,
        ?ServerManager $serverManager,
    ): void {
        $diagnostics = $serverManager?->diagnostics() ?? '';
        if ($diagnostics === '') {
            return;
        }

        // Capped, since one repeating warning per operation would otherwise bury the run's own output.
        if (strlen($diagnostics) > self::MAX_DIAGNOSTIC_BYTES) {
            $diagnostics = '(truncated) ...' . substr($diagnostics, -self::MAX_DIAGNOSTIC_BYTES);
        }

        $progress->writeln('<comment>Server output during the run:</comment>');
        $progress->writeln($diagnostics);
    }

    private function progressChannel(OutputInterface $output): OutputInterface
    {
        if ($output instanceof ConsoleOutputInterface) {
            return $output->getErrorOutput();
        }

        return $output;
    }

    private function describeServerStart(): string
    {
        $seedSuffix = $this->config->seedEntries > 0
            ? sprintf(', seed-entries=%d', $this->config->seedEntries)
            : '';

        return sprintf(
            'Starting server (backend=%s, runner=%s, port=%d%s)...',
            $this->config->backend,
            $this->config->runner,
            $this->config->port,
            $seedSuffix,
        );
    }

    private function describeRunStart(): string
    {
        $budget = $this->config->duration !== null
            ? sprintf('duration=%ds', $this->config->duration)
            : sprintf('ops/client=%d', $this->config->ops);

        return sprintf(
            'Running load test: clients=%d (forked), warmup=%ds, %s...',
            $this->config->clients,
            $this->config->warmup,
            $budget,
        );
    }

    /**
     * Fork one process per client, barrier on readiness, broadcast the schedule, then merge their snapshots.
     */
    private function runForkPool(WorkloadMix $mix): StatsSnapshot
    {
        pcntl_signal(SIGPIPE, SIG_IGN);

        $children = $this->forkChildren($mix);
        $allReady = $this->awaitReady($children);

        $goTime = microtime(true);
        $recordStart = $goTime + $this->config->warmup;
        $deadline = $this->config->duration !== null
            ? $recordStart + (float) $this->config->duration
            : null;

        $this->broadcastGo(
            $children,
            $allReady,
            $recordStart,
            $deadline,
        );

        $failures = $this->awaitChildren($children);
        $elapsed = microtime(true) - $recordStart;

        if (!$allReady) {
            throw new RuntimeException(sprintf(
                'One or more of the %d load-test workers failed to connect to the server.',
                $this->config->clients,
            ));
        }

        if ($failures !== []) {
            throw new RuntimeException(sprintf(
                '%d of %d load-test workers terminated abnormally: %s',
                count($failures),
                $this->config->clients,
                implode('; ', $failures),
            ));
        }

        return StatsSnapshot::merge(
            $this->collectSnapshots($children),
            $elapsed,
        );
    }

    /**
     * @return list<array{pid: int, ready: resource, go: resource, result: string, id: int}>
     */
    private function forkChildren(WorkloadMix $mix): array
    {
        $children = [];

        for ($i = 0; $i < $this->config->clients; $i++) {
            [$parentReady, $childReady] = $this->socketPair();
            [$parentGo, $childGo] = $this->socketPair();
            $resultPath = sprintf(
                '%s/freedsx_loadtest_%d_%d.dat',
                sys_get_temp_dir(),
                getmypid(),
                $i,
            );

            $pid = pcntl_fork();
            if ($pid === -1) {
                throw new RuntimeException('Failed to fork a load-test worker process.');
            }

            if ($pid === 0) {
                fclose($parentReady);
                fclose($parentGo);
                $this->runChild(
                    $this->config->workerIdOffset + $i,
                    $mix,
                    $childReady,
                    $childGo,
                    $resultPath,
                );

                exit(0);
            }

            fclose($childReady);
            fclose($childGo);
            $children[] = [
                'pid' => $pid,
                'ready' => $parentReady,
                'go' => $parentGo,
                'result' => $resultPath,
                'id' => $i,
            ];
        }

        return $children;
    }

    /**
     * @param resource $readySocket
     * @param resource $goSocket
     */
    private function runChild(
        int $workerId,
        WorkloadMix $mix,
        $readySocket,
        $goSocket,
        string $resultPath,
    ): void {
        $this->seedChildRng($workerId);

        $stats = new StatsCollector();
        $worker = new Worker(
            workerId: $workerId,
            config: $this->config,
            mix: $mix,
            stats: $stats,
            opsCap: $this->config->ops,
        );

        try {
            $client = $worker->connect();
        } catch (Throwable) {
            fwrite($readySocket, '0');
            fgets($goSocket); // wait for the broadcast so the parent's write never SIGPIPEs
            fclose($goSocket);

            return;
        }

        fwrite($readySocket, '1');
        $signal = $this->awaitGo($goSocket);

        if (!$signal['proceed']) {
            $worker->disconnect($client);

            return;
        }

        try {
            $worker->run(
                $client,
                $signal['recordStart'],
                $signal['deadline'],
            );
        } finally {
            $stats->stopRecording();
            $worker->disconnect($client);
        }

        file_put_contents(
            $resultPath,
            serialize($stats->snapshot(0.0)),
        );
    }

    private function seedChildRng(int $workerId): void
    {
        if ($this->config->rngSeed !== null) {
            mt_srand($this->config->rngSeed + $workerId);

            return;
        }

        // Forked children inherit an identical mt_rand state; reseed each distinctly by its own PID.
        mt_srand(((int) getmypid()) * 7919 + $workerId);
    }

    /**
     * @param list<array{pid: int, ready: resource, go: resource, result: string, id: int}> $children
     */
    private function awaitReady(array $children): bool
    {
        $allReady = true;

        foreach ($children as $child) {
            if (fread($child['ready'], 1) !== '1') {
                $allReady = false;
            }
        }

        return $allReady;
    }

    /**
     * @param list<array{pid: int, ready: resource, go: resource, result: string, id: int}> $children
     */
    private function broadcastGo(
        array $children,
        bool $proceed,
        float $recordStart,
        ?float $deadline,
    ): void {
        $message = sprintf(
            "%d %.6f %s\n",
            $proceed ? 1 : 0,
            $recordStart,
            $deadline !== null ? sprintf('%.6f', $deadline) : '-',
        );

        foreach ($children as $child) {
            fwrite($child['go'], $message);
            fclose($child['go']);
        }
    }

    /**
     * @param resource $goSocket
     *
     * @return array{proceed: bool, recordStart: float, deadline: float|null}
     */
    private function awaitGo($goSocket): array
    {
        $line = fgets($goSocket);
        fclose($goSocket);

        $parts = is_string($line)
            ? explode(' ', trim($line))
            : [];

        if (count($parts) < 3) {
            return ['proceed' => false, 'recordStart' => 0.0, 'deadline' => null];
        }

        return [
            'proceed' => $parts[0] === '1',
            'recordStart' => (float) $parts[1],
            'deadline' => $parts[2] === '-' ? null : (float) $parts[2],
        ];
    }

    /**
     * @param list<array{pid: int, ready: resource, go: resource, result: string, id: int}> $children
     *
     * @return list<string> descriptions of any workers that crashed or exited non-zero
     */
    private function awaitChildren(array $children): array
    {
        $failures = [];

        foreach ($children as $child) {
            $status = 0;
            pcntl_waitpid($child['pid'], $status);

            if (!is_int($status)) {
                continue;
            }

            if (pcntl_wifsignaled($status)) {
                $failures[] = sprintf(
                    'worker %d killed by signal %d',
                    $child['id'],
                    pcntl_wtermsig($status),
                );

                continue;
            }

            $exit = pcntl_wexitstatus($status);
            if ($exit !== 0) {
                $failures[] = sprintf(
                    'worker %d exited with status %d',
                    $child['id'],
                    $exit,
                );
            }
        }

        return $failures;
    }

    /**
     * @param list<array{pid: int, ready: resource, go: resource, result: string, id: int}> $children
     *
     * @return list<StatsSnapshot>
     */
    private function collectSnapshots(array $children): array
    {
        $snapshots = [];

        foreach ($children as $child) {
            if (!is_file($child['result'])) {
                continue;
            }

            $raw = file_get_contents($child['result']);
            @unlink($child['result']);
            $snapshot = is_string($raw)
                ? unserialize($raw, ['allowed_classes' => [StatsSnapshot::class]])
                : false;

            if ($snapshot instanceof StatsSnapshot) {
                $snapshots[] = $snapshot;
            }
        }

        return $snapshots;
    }

    /**
     * @return array<resource>
     */
    private function socketPair(): array
    {
        $pair = stream_socket_pair(
            STREAM_PF_UNIX,
            STREAM_SOCK_STREAM,
            0,
        );

        if ($pair === false) {
            throw new RuntimeException('Failed to create a socket pair for worker coordination.');
        }

        return $pair;
    }

    private function assertPcntlAvailable(): void
    {
        if (function_exists('pcntl_fork') && function_exists('pcntl_waitpid')) {
            return;
        }

        throw new RuntimeException(
            'The load-test driver requires ext-pcntl to fork one process per concurrent client.',
        );
    }
}
