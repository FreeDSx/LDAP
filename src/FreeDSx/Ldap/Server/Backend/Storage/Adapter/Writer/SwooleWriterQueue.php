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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer;

use Closure;
use FreeDSx\Ldap\Exception\RuntimeException;
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Throwable;

/**
 * Funnels write closures from many coroutines through a single writer coroutine.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SwooleWriterQueue implements WriterQueueInterface
{
    /**
     * Idle seconds before the writer exits cleanly so it never outlives the coroutine scope it was spawned in.
     */
    private const IDLE_TIMEOUT_SECONDS = 1.0;

    /**
     * @var Channel<array{Closure, Channel<mixed>}>|null
     */
    private ?Channel $jobs = null;

    private bool $started = false;

    private readonly WriteScope $scope;

    /**
     * @param Closure(Closure(): void): void|null $batchWrapper Wraps a batch of jobs in an outer transaction.
     */
    public function __construct(
        private readonly int $capacity = 1024,
        private readonly ?Closure $batchWrapper = null,
    ) {
        $this->scope = new WriteScope();
    }

    public function __destruct()
    {
        $this->jobs?->close();
    }

    /**
     * Submit a write closure and block the caller until the writer reports completion.
     *
     * @throws Throwable
     */
    public function run(Closure $job): void
    {
        $this->ensureStarted();

        $reply = new Channel(1);

        $this->jobs?->push([
            $job,
            $reply,
        ]);
        $result = $reply->pop();

        if ($result instanceof Throwable) {
            throw $result;
        }
    }

    public function isWriter(): bool
    {
        return $this->scope->isActive();
    }

    /**
     * Closing the channel wakes the writer out of its idle wait, so it exits now rather than a timeout later.
     *
     * Every accepted job has already been replied to by the time run() returns, so there is never one in flight here.
     */
    public function drain(): void
    {
        $jobs = $this->jobs;
        if ($jobs === null) {
            return;
        }

        $this->jobs = null;
        $this->started = false;

        $jobs->close();
    }

    /**
     * Executes a batch under a single outer transaction, isolating per-job failures via savepoints.
     *
     * @internal
     *
     * @param list<array{Closure, Channel<mixed>}> $batch
     * @param Closure(Closure(): void): void $batchWrapper
     */
    public static function executeBatch(
        array $batch,
        Closure $batchWrapper,
    ): void {
        $results = array_fill(
            0,
            count($batch),
            true,
        );

        try {
            $batchWrapper(static function () use ($batch, &$results): void {
                foreach ($batch as $i => [$closure]) {
                    try {
                        $closure();
                    } catch (Throwable $e) {
                        $results[$i] = $e;
                    }
                }
            });
        } catch (Throwable $e) {
            foreach ($batch as [, $reply]) {
                $reply->push($e);
            }

            return;
        }

        foreach ($batch as $i => [, $reply]) {
            $reply->push($results[$i]);
        }
    }

    private function ensureStarted(): void
    {
        if ($this->started) {
            return;
        }

        if (Coroutine::getCid() === -1) {
            throw new RuntimeException(
                self::class . ' can only be used inside a Swoole coroutine.',
            );
        }

        $this->jobs = new Channel($this->capacity);
        $this->started = true;
        $this->spawnWriter($this->jobs);
    }

    /**
     * @param Channel<array{Closure, Channel<mixed>}> $jobs
     */
    private function spawnWriter(Channel $jobs): void
    {
        $batchWrapper = $this->batchWrapper;
        $executeBatch = self::executeBatch(...);

        // Only the writer still holding the current channel may clear the state
        $onExit = function () use ($jobs): void {
            if ($this->jobs !== $jobs) {
                return;
            }

            $this->jobs = null;
            $this->started = false;
        };

        Coroutine::create(function () use ($jobs, $batchWrapper, $executeBatch, $onExit): void {
            // Held for the writer's whole life, so anything a job runs can tell it is already on the writer.
            $this->scope->enter();

            try {
                while (true) {
                    $first = $jobs->pop(self::IDLE_TIMEOUT_SECONDS);
                    if ($first === false) {
                        return;
                    }

                    $batch = [$first];
                    while (!$jobs->isEmpty()) {
                        $next = $jobs->pop();
                        if ($next === false) {
                            break;
                        }
                        $batch[] = $next;
                    }

                    if (count($batch) === 1 || $batchWrapper === null) {
                        foreach ($batch as [$closure, $reply]) {
                            try {
                                $closure();
                                $reply->push(true);
                            } catch (Throwable $e) {
                                $reply->push($e);
                            }
                        }
                    } else {
                        $executeBatch(
                            $batch,
                            $batchWrapper,
                        );
                    }
                }
            } finally {
                $this->scope->leave();
                $onExit();
            }
        });
    }
}
