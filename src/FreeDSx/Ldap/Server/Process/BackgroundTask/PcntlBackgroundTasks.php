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

namespace FreeDSx\Ldap\Server\Process\BackgroundTask;

use Closure;
use Psr\Log\LoggerInterface;

use function microtime;
use function pcntl_fork;
use function pcntl_waitpid;
use function posix_getpid;
use function posix_kill;
use function sprintf;
use function usleep;

use const SIGTERM;
use const WNOHANG;

/**
 * Runs periodic and long-lived background tasks as forked child processes under PCNTL.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PcntlBackgroundTasks implements BackgroundTasksInterface
{
    /**
     * @var array<int, PeriodicTaskState>
     */
    private array $periodicState = [];

    /**
     * @var array<int, ?int>
     */
    private array $longLivedPids = [];

    private Closure $childStart;

    /**
     * Only the owner PID may interact with the tasks it created.
     */
    private readonly int $ownerPid;

    /**
     * @param list<PeriodicTask> $periodicTasks
     * @param list<LongLivedTask> $longLivedTasks
     */
    public function __construct(
        private readonly array $periodicTasks,
        private readonly array $longLivedTasks,
        private readonly ?LoggerInterface $logger = null,
        private readonly int $gracefulStopSeconds = 0,
    ) {
        $this->childStart = static function (): void {};
        $this->ownerPid = posix_getpid();
    }

    public function onChildStart(Closure $onStart): void
    {
        $this->childStart = $onStart;
    }

    public function start(): void
    {
        if (!$this->ownsTasks()) {
            return;
        }

        foreach ($this->longLivedTasks as $index => $task) {
            $this->longLivedPids[$index] = $this->fork($task->run);
        }
    }

    public function tick(): void
    {
        if (!$this->ownsTasks()) {
            return;
        }

        $this->reapLongLived();
        $this->maintainPeriodic();
    }

    public function stop(): void
    {
        if (!$this->ownsTasks()) {
            return;
        }
        $pids = [];

        foreach ($this->longLivedTasks as $index => $task) {
            $pid = $this->longLivedPids[$index] ?? null;

            if ($pid !== null) {
                $pids[] = $pid;
            }

            $this->longLivedPids[$index] = null;
        }

        foreach ($this->periodicState as $state) {
            if ($state->pid !== null) {
                $pids[] = $state->pid;
            }

            $state->pid = null;
        }

        $this->endChildren($pids);
    }

    /**
     * Signal every task to stop, wait up to the graceful budget for them to exit, then force-kill any stragglers.
     *
     * @param list<int> $pids
     */
    private function endChildren(array $pids): void
    {
        foreach ($pids as $pid) {
            posix_kill(
                $pid,
                SIGTERM,
            );
        }

        $deadline = microtime(true) + $this->gracefulStopSeconds;
        $pending = $pids;
        while ($pending !== [] && microtime(true) < $deadline) {
            $pending = $this->reapExited($pending);
            if ($pending !== []) {
                usleep(10000);
            }
        }

        foreach ($pending as $pid) {
            posix_kill(
                $pid,
                SIGKILL,
            );
            $status = 0;
            pcntl_waitpid(
                $pid,
                $status,
            );
        }
    }

    /**
     * @param list<int> $pids
     * @return list<int> those not yet reaped
     */
    private function reapExited(array $pids): array
    {
        $pending = [];

        foreach ($pids as $pid) {
            $status = 0;

            if (pcntl_waitpid($pid, $status, WNOHANG) === 0) {
                $pending[] = $pid;
            }
        }

        return $pending;
    }

    /**
     * On each task's cadence, fork a short-lived child to do one iteration so the parent keeps accepting.
     */
    private function maintainPeriodic(): void
    {
        $now = microtime(true);

        foreach ($this->periodicTasks as $index => $task) {
            $state = $this->periodicState[$index] ??= new PeriodicTaskState($now);

            if ($state->pid !== null && $this->pidExited($state->pid)) {
                $state->pid = null;
            }
            if ($state->pid !== null || ($now - $state->lastRunAt) < $task->intervalSeconds) {
                continue;
            }

            $state->lastRunAt = $now;
            $state->pid = $this->fork($task->run);
        }
    }

    private function reapLongLived(): void
    {
        foreach ($this->longLivedTasks as $index => $task) {
            $pid = $this->longLivedPids[$index] ?? null;
            if ($pid === null || !$this->pidExited($pid)) {
                continue;
            }

            $this->longLivedPids[$index] = null;
            $this->logger?->warning(sprintf(
                'The "%s" background task exited unexpectedly.',
                $task->name,
            ));
        }
    }

    /**
     * @param Closure(): void $childBody
     */
    private function fork(Closure $childBody): ?int
    {
        $pid = pcntl_fork();

        if ($pid === -1) {
            $this->logger?->warning('Unable to fork a background task.');

            return null;
        }

        if ($pid === 0) {
            ($this->childStart)();
            $childBody();
            exit(0);
        }

        return $pid;
    }

    private function ownsTasks(): bool
    {
        return posix_getpid() === $this->ownerPid;
    }

    private function pidExited(?int $pid): bool
    {
        if ($pid === null) {
            return false;
        }

        $status = 0;
        $result = pcntl_waitpid(
            $pid,
            $status,
            WNOHANG,
        );

        return $result === -1 || $result > 0;
    }
}
