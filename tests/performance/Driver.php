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

use RuntimeException;
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\WaitGroup;
use Swoole\Runtime;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

/**
 * Orchestrates a load-test run end-to-end: server lifecycle, coroutine pool, warmup timer,
 * barrier + deadline coordination, then a rendered report.
 */
final class Driver
{
    public function __construct(
        private readonly Config $config,
    ) {
    }

    public function run(OutputInterface $output): void
    {
        $this->assertSwooleAvailable();

        if ($this->config->seed !== null) {
            mt_srand($this->config->seed);
        }

        $progress = $this->progressChannel($output);
        $mix = new WorkloadMix($this->config->mix);
        $stats = new StatsCollector();
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
            $snapshot = $this->runCoroutinePool($mix, $stats);
        } finally {
            $serverManager?->stop();
        }

        (new Report($this->config, $mix, $snapshot))->render($output);
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
            'Running load test: clients=%d, warmup=%ds, %s...',
            $this->config->clients,
            $this->config->warmup,
            $budget,
        );
    }

    private function runCoroutinePool(WorkloadMix $mix, StatsCollector $stats): StatsSnapshot
    {
        Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

        $elapsedSeconds = 0.0;
        $workerErrors = [];

        Coroutine\run(function () use ($mix, $stats, &$elapsedSeconds, &$workerErrors): void {
            $clients = $this->config->clients;
            $readyBarrier = new Channel($clients);
            $startSignal = new Channel($clients);
            $waitGroup = new WaitGroup();

            for ($i = 0; $i < $clients; $i++) {
                $waitGroup->add();
                $workerId = $i;
                Coroutine::create(function () use ($workerId, $mix, $stats, $readyBarrier, $startSignal, $waitGroup, &$workerErrors): void {
                    try {
                        (new Worker(
                            workerId: $workerId,
                            config: $this->config,
                            mix: $mix,
                            stats: $stats,
                            readyBarrier: $readyBarrier,
                            startSignal: $startSignal,
                            opsCap: $this->config->ops,
                        ))->run();
                    } catch (Throwable $e) {
                        $workerErrors[] = $e;
                    } finally {
                        $waitGroup->done();
                    }
                });
            }

            $allReady = $this->awaitReady($readyBarrier, $clients);

            $deadline = $this->config->duration !== null
                ? microtime(true) + $this->config->warmup + (float) $this->config->duration
                : null;

            for ($i = 0; $i < $clients; $i++) {
                $startSignal->push($allReady ? $deadline : false);
            }

            if ($allReady) {
                $elapsedSeconds = $this->driveWarmupAndRecord($stats, $waitGroup);
            } else {
                $waitGroup->wait();
            }
        });

        if ($workerErrors !== []) {
            $first = $workerErrors[0];
            throw new RuntimeException(sprintf(
                '%d of %d workers failed; first error: %s: %s',
                count($workerErrors),
                $this->config->clients,
                $first::class,
                $first->getMessage()
            ), 0, $first);
        }

        return $stats->snapshot($elapsedSeconds);
    }

    private function awaitReady(Channel $readyBarrier, int $expected): bool
    {
        $allReady = true;

        for ($i = 0; $i < $expected; $i++) {
            $ready = $readyBarrier->pop();

            if ($ready !== true) {
                $allReady = false;
            }
        }

        return $allReady;
    }

    private function driveWarmupAndRecord(StatsCollector $stats, WaitGroup $waitGroup): float
    {
        $recordingStart = 0.0;

        Coroutine::create(function () use ($stats, &$recordingStart): void {
            if ($this->config->warmup > 0) {
                Coroutine::sleep((float) $this->config->warmup);
            }

            $recordingStart = microtime(true);
            $stats->startRecording();
        });

        $waitGroup->wait();

        $stats->stopRecording();

        return $recordingStart > 0.0
            ? microtime(true) - $recordingStart
            : 0.0;
    }

    private function assertSwooleAvailable(): void
    {
        if (extension_loaded('swoole')) {
            return;
        }

        throw new RuntimeException(
            'The load-test driver requires ext-swoole for concurrent coroutine-based clients. '
            . 'Install via PECL: pecl install swoole (^5.1 for PHP 8.3/8.4, ^6.0 for PHP 8.5+).'
        );
    }
}
