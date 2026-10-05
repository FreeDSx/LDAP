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

namespace Tests\Unit\FreeDSx\Ldap\Server\Process\BackgroundTask;

use Closure;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Process\BackgroundTask\LongLivedTask;
use FreeDSx\Ldap\Server\Process\BackgroundTask\SwooleBackgroundTasks;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;
use RuntimeException;
use Swoole\Coroutine;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;

final class SwooleBackgroundTasksTest extends TestCase
{
    use RequiresExtensionsTrait;

    private RecordingLogger $logger;

    private EventLogger $eventLogger;

    protected function setUp(): void
    {
        $this->requireSwoole();

        $this->logger = new RecordingLogger();
        $this->eventLogger = new EventLogger(
            $this->logger,
            EventLogPolicy::default(),
        );
    }

    public function test_a_long_lived_task_that_throws_is_recorded_as_an_error_with_its_cause(): void
    {
        $this->start($this->tasksRunning(static function (): void {
            throw new RuntimeException('Task failure.');
        }));

        $context = $this->onlyFailureContext();
        self::assertSame(
            'error',
            $context[EventContext::REASON],
        );
        self::assertSame(
            RuntimeException::class,
            $context[EventContext::EXCEPTION_CLASS],
        );
    }

    public function test_a_long_lived_task_that_returns_before_shutdown_is_recorded_as_exited(): void
    {
        $this->start($this->tasksRunning(static function (): void {}));

        self::assertSame(
            'exited',
            $this->onlyFailureContext()[EventContext::REASON],
        );
    }

    public function test_a_long_lived_task_that_returns_after_shutdown_is_not_recorded(): void
    {
        $subject = null;
        $subject = $this->tasksRunning(static function () use (&$subject): void {
            $subject?->stop();
        });

        $this->start($subject);

        self::assertSame(
            [],
            $this->logger->records,
        );
    }

    /**
     * @param Closure(): void $run
     */
    private function tasksRunning(Closure $run): SwooleBackgroundTasks
    {
        return new SwooleBackgroundTasks(
            [],
            [
                new LongLivedTask(
                    'test-task',
                    $run,
                ),
            ],
            $this->eventLogger,
        );
    }

    private function start(SwooleBackgroundTasks $subject): void
    {
        Coroutine\run(static function () use ($subject): void {
            $subject->start();
        });
    }

    /**
     * @return array<string, mixed>
     */
    private function onlyFailureContext(): array
    {
        self::assertCount(
            1,
            $this->logger->records,
        );
        $record = $this->logger->records[0];
        self::assertSame(
            LogLevel::ERROR,
            $record['level'],
        );
        self::assertSame(
            ServerEvent::TaskFailed->value,
            $record['context'][EventContext::EVENT],
        );
        self::assertSame(
            'test-task',
            $record['context']['task'],
        );

        return $record['context'];
    }
}
