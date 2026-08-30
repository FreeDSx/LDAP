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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer;

use Closure;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\SwooleWriterQueue;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use LogicException;
use PHPUnit\Framework\TestCase;
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;
use Throwable;

final class SwooleWriterQueueTest extends TestCase
{
    use RequiresExtensionsTrait;

    protected function setUp(): void
    {
        $this->requireSwoole();
    }

    public function test_throws_when_called_outside_a_coroutine(): void
    {
        $queue = new SwooleWriterQueue();

        $this->expectException(RuntimeException::class);
        $queue->run(static fn() => null);
    }

    public function test_single_job_executes_successfully(): void
    {
        $executed = false;

        Coroutine\run(function () use (&$executed): void {
            $queue = new SwooleWriterQueue();
            $queue->run(static function () use (&$executed): void {
                $executed = true;
            });
        });

        self::assertTrue($executed);
    }

    public function test_is_writer_is_false_before_any_job_runs(): void
    {
        $queue = new SwooleWriterQueue();

        self::assertFalse($queue->isWriter());
    }

    public function test_is_writer_is_true_inside_a_job(): void
    {
        $observed = null;

        Coroutine\run(function () use (&$observed): void {
            $queue = new SwooleWriterQueue();
            $queue->run(static function () use ($queue, &$observed): void {
                $observed = $queue->isWriter();
            });
        });

        self::assertTrue($observed);
    }

    /**
     * The submitter is blocked on the reply while its job runs, so treating it as the writer would route it wrongly.
     */
    public function test_is_writer_is_false_on_the_coroutine_that_submitted_the_job(): void
    {
        $observed = null;

        Coroutine\run(function () use (&$observed): void {
            $queue = new SwooleWriterQueue();
            $queue->run(static fn() => null);
            $observed = $queue->isWriter();
        });

        self::assertFalse($observed);
    }

    public function test_run_rethrows_job_exception_to_caller(): void
    {
        $thrown = null;

        Coroutine\run(function () use (&$thrown): void {
            $queue = new SwooleWriterQueue();

            try {
                $queue->run(static function (): void {
                    throw new LogicException('job failed');
                });
            } catch (LogicException $e) {
                $thrown = $e;
            }
        });

        self::assertNotNull($thrown);
        self::assertSame(
            'job failed',
            $thrown->getMessage(),
        );
    }

    public function test_single_job_does_not_invoke_batch_wrapper(): void
    {
        $wrapperCalls = 0;
        $batchWrapper = static function (Closure $cb) use (&$wrapperCalls): void {
            $wrapperCalls++;
            $cb();
        };

        Coroutine\run(function () use ($batchWrapper): void {
            $queue = new SwooleWriterQueue(batchWrapper: $batchWrapper);
            $queue->run(static fn() => null);
        });

        self::assertSame(
            0,
            $wrapperCalls,
        );
    }

    public function test_executeBatch_calls_wrapper_once_and_runs_all_closures(): void
    {
        $wrapperCalls = 0;
        $executed = [];
        $batchWrapper = static function (Closure $cb) use (&$wrapperCalls): void {
            $wrapperCalls++;
            $cb();
        };

        Coroutine\run(function () use ($batchWrapper, &$executed): void {
            $replies = [new Channel(1), new Channel(1), new Channel(1)];
            $batch = [
                [static function () use (&$executed): void {
                    $executed[] = 'a';
                }, $replies[0]],
                [static function () use (&$executed): void {
                    $executed[] = 'b';
                }, $replies[1]],
                [static function () use (&$executed): void {
                    $executed[] = 'c';
                }, $replies[2]],
            ];

            SwooleWriterQueue::executeBatch($batch, $batchWrapper);

            foreach ($replies as $reply) {
                $reply->pop();
            }
        });

        self::assertSame(
            1,
            $wrapperCalls,
        );
        self::assertSame(
            ['a', 'b', 'c'],
            $executed,
        );
    }

    public function test_executeBatch_isolates_per_job_failure(): void
    {
        $batchWrapper = static function (Closure $cb): void {
            $cb();
        };
        $results = [];

        Coroutine\run(function () use ($batchWrapper, &$results): void {
            $replies = [new Channel(1), new Channel(1), new Channel(1)];
            $batch = [
                [static fn() => null, $replies[0]],
                [static function (): void {
                    throw new LogicException('b failed');
                }, $replies[1]],
                [static fn() => null, $replies[2]],
            ];

            SwooleWriterQueue::executeBatch($batch, $batchWrapper);

            $results[0] = $replies[0]->pop();
            $results[1] = $replies[1]->pop();
            $results[2] = $replies[2]->pop();
        });

        self::assertTrue($results[0]);
        self::assertInstanceOf(LogicException::class, $results[1]);
        self::assertSame('b failed', $results[1]->getMessage());
        self::assertTrue($results[2]);
    }

    public function test_executeBatch_broadcasts_wrapper_failure_to_all_callers(): void
    {
        $batchWrapper = static function (Closure $cb): void {
            throw new LogicException('transaction failed');
        };
        $results = [];

        Coroutine\run(function () use ($batchWrapper, &$results): void {
            $replies = [new Channel(1), new Channel(1), new Channel(1)];
            $batch = [
                [static fn() => null, $replies[0]],
                [static fn() => null, $replies[1]],
                [static fn() => null, $replies[2]],
            ];

            SwooleWriterQueue::executeBatch($batch, $batchWrapper);

            $results[0] = $replies[0]->pop();
            $results[1] = $replies[1]->pop();
            $results[2] = $replies[2]->pop();
        });

        foreach ($results as $result) {
            self::assertInstanceOf(LogicException::class, $result);
            self::assertSame('transaction failed', $result->getMessage());
        }
    }

    public function test_executeBatch_reports_no_success_when_the_transaction_is_discarded_after_the_jobs_ran(): void
    {
        // The shape a deadlock produces: every job runs, then the transaction that held them all is rolled back.
        $batchWrapper = static function (Closure $cb): void {
            $cb();

            throw new LogicException('deadlock rolled the transaction back');
        };
        $results = [];

        Coroutine\run(function () use ($batchWrapper, &$results): void {
            $replies = [new Channel(1), new Channel(1), new Channel(1)];
            $batch = [
                [static fn() => null, $replies[0]],
                [static fn() => null, $replies[1]],
                [static fn() => null, $replies[2]],
            ];

            SwooleWriterQueue::executeBatch($batch, $batchWrapper);

            $results[0] = $replies[0]->pop();
            $results[1] = $replies[1]->pop();
            $results[2] = $replies[2]->pop();
        });

        foreach ($results as $result) {
            self::assertInstanceOf(
                LogicException::class,
                $result,
                'A job whose write was rolled back must never be told it succeeded.',
            );
        }
    }

    public function test_executeBatch_does_not_carry_a_failure_from_an_earlier_attempt(): void
    {
        // Stands in for the retry loop, which reissues the whole batch on a transient conflict.
        $batchWrapper = static function (Closure $cb): void {
            $cb();
            $cb();
        };
        $attempts = 0;
        $results = [];

        Coroutine\run(function () use ($batchWrapper, &$attempts, &$results): void {
            $replies = [new Channel(1), new Channel(1)];
            $batch = [
                [static fn() => null, $replies[0]],
                [static function () use (&$attempts): void {
                    $attempts++;

                    if ($attempts === 1) {
                        throw new LogicException('conflicted on the first attempt');
                    }
                }, $replies[1]],
            ];

            SwooleWriterQueue::executeBatch($batch, $batchWrapper);

            $results[0] = $replies[0]->pop();
            $results[1] = $replies[1]->pop();
        });

        self::assertTrue($results[0]);
        self::assertTrue(
            $results[1],
            'A job that succeeded on the reissued attempt must not report the earlier attempt failure.',
        );
    }

    public function test_executeBatch_reports_failure_when_the_wrapper_never_runs_the_jobs(): void
    {
        $batchWrapper = static function (Closure $cb): void {};
        $results = [];

        Coroutine\run(function () use ($batchWrapper, &$results): void {
            $replies = [new Channel(1), new Channel(1)];
            $batch = [
                [static fn() => null, $replies[0]],
                [static fn() => null, $replies[1]],
            ];

            SwooleWriterQueue::executeBatch($batch, $batchWrapper);

            $results[0] = $replies[0]->pop();
            $results[1] = $replies[1]->pop();
        });

        foreach ($results as $result) {
            self::assertInstanceOf(
                StorageIoException::class,
                $result,
            );
        }
    }

    public function test_concurrent_job_failure_isolates_to_failing_caller(): void
    {
        $batchWrapper = static function (Closure $cb): void {
            $cb();
        };
        $results = [];

        Coroutine\run(function () use ($batchWrapper, &$results): void {
            $queue = new SwooleWriterQueue(batchWrapper: $batchWrapper);
            $done = new Channel(3);

            Coroutine::create(function () use ($queue, $done, &$results): void {
                try {
                    $queue->run(static fn() => null);
                    $results['a'] = true;
                } catch (Throwable $e) {
                    $results['a'] = $e;
                }
                $done->push('a');
            });
            Coroutine::create(function () use ($queue, $done, &$results): void {
                try {
                    $queue->run(static function (): void {
                        throw new LogicException('job b failed');
                    });
                    $results['b'] = true;
                } catch (Throwable $e) {
                    $results['b'] = $e;
                }
                $done->push('b');
            });
            Coroutine::create(function () use ($queue, $done, &$results): void {
                try {
                    $queue->run(static fn() => null);
                    $results['c'] = true;
                } catch (Throwable $e) {
                    $results['c'] = $e;
                }
                $done->push('c');
            });

            for ($i = 0; $i < 3; $i++) {
                $done->pop();
            }
        });

        self::assertTrue($results['a']);
        self::assertInstanceOf(LogicException::class, $results['b']);
        self::assertSame(
            'job b failed',
            $results['b']->getMessage(),
        );
        self::assertTrue($results['c']);
    }
}
