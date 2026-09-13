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
use FreeDSx\Ldap\Server\Logging\ExceptionLogging;
use Psr\Log\LoggerInterface;
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Throwable;

use function sprintf;

/**
 * Runs periodic and long-lived background tasks as background coroutines under Swoole.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SwooleBackgroundTasks implements BackgroundTasksInterface
{
    private bool $stopping = false;

    /**
     * @var list<Channel<mixed>>
     */
    private array $wakeups = [];

    /**
     * @param list<PeriodicTask> $periodicTasks
     * @param list<LongLivedTask> $longLivedTasks
     */
    public function __construct(
        private readonly array $periodicTasks,
        private readonly array $longLivedTasks,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    public function onChildStart(Closure $onStart): void
    {
        // Coroutine workers share the parent's memory; there is nothing to release.
    }

    public function start(): void
    {
        foreach ($this->periodicTasks as $task) {
            $this->startPeriodic($task);
        }
        foreach ($this->longLivedTasks as $task) {
            Coroutine::create(fn(): null => $this->guard($task->name, $task->run));
        }
    }

    public function tick(): void
    {
        // Coroutines are self-managing; there is nothing to reap between accepts.
    }

    public function stop(): void
    {
        $this->stopping = true;

        foreach ($this->wakeups as $wakeup) {
            $wakeup->push(true);
        }
        foreach ($this->longLivedTasks as $task) {
            if ($task->stop !== null) {
                ($task->stop)();
            }
        }
    }

    private function startPeriodic(PeriodicTask $task): void
    {
        $wakeup = new Channel(1);
        $this->wakeups[] = $wakeup;

        Coroutine::create(function () use ($task, $wakeup): void {
            while (!$this->stopping) {
                // pop() returns the pushed value on shutdown, or false after the interval elapses.
                if ($wakeup->pop($task->intervalSeconds) !== false) {
                    break;
                }

                $this->guard($task->name, $task->run);
            }
        });
    }

    /**
     * Run a task body, logging any failure by name so an unhandled exception does not silently kill the coroutine.
     *
     * @param Closure(): void $run
     */
    private function guard(
        string $name,
        Closure $run,
    ): void {
        try {
            $run();
        } catch (Throwable $e) {
            $this->logger?->error(
                sprintf('The "%s" background task failed.', $name),
                ExceptionLogging::makeLogContext($e),
            );
        }
    }
}
