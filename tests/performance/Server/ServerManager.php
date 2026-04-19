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

namespace Tests\Performance\FreeDSx\Ldap\Server;

use RuntimeException;
use Symfony\Component\Process\Process;
use Tests\Performance\FreeDSx\Ldap\Config;

/**
 * Spawns ldap-backend-storage.php, waits for the readiness marker, and stops it on destruction.
 */
final class ServerManager
{
    private const READY_MARKER = 'server starting...';

    private const POLL_INTERVAL_US = 15_000;

    private const BOOTSTRAP_PATH = __DIR__ . '/../../bin/ldap-backend-storage.php';

    private ?Process $process = null;

    public function __construct(
        private readonly Config $config,
        private readonly int $maxWaitSeconds = 10,
    ) {
    }

    private function readyDeadlineSeconds(): int
    {
        return $this->maxWaitSeconds + (int) ceil($this->config->seedEntries / 100);
    }

    public function start(): void
    {
        if ($this->process !== null) {
            throw new RuntimeException('ServerManager::start() called twice.');
        }

        $this->process = new Process([
            'php',
            '-dpcov.enabled=0',
            self::BOOTSTRAP_PATH,
            'tcp',
            '--storage=' . $this->config->backend,
            '--runner=' . $this->config->runner,
            '--port=' . $this->config->port,
            '--seed-entries=' . $this->config->seedEntries,
        ]);

        $this->process->start();

        $this->awaitReady($this->process);
    }

    public function stop(): void
    {
        if ($this->process === null) {
            return;
        }

        $this->process->stop();
        $this->process = null;
    }

    public function __destruct()
    {
        $this->stop();
    }

    private function awaitReady(Process $process): void
    {
        $waitSeconds = $this->readyDeadlineSeconds();
        $deadline = microtime(true) + $waitSeconds;

        while ($process->isRunning()) {
            $output = $process->getOutput();

            if (str_contains($output, self::READY_MARKER)) {
                $process->clearOutput();

                return;
            }

            if (microtime(true) >= $deadline) {
                break;
            }

            usleep(self::POLL_INTERVAL_US);
        }

        $process->stop();
        throw new RuntimeException(sprintf(
            "Server did not emit '%s' within %d seconds. Stderr: %s",
            self::READY_MARKER,
            $waitSeconds,
            PHP_EOL . $process->getErrorOutput()
        ));
    }
}
