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

namespace Tests\Unit\FreeDSx\Ldap\Server\Metrics\Rollup;

use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Metrics\Observation\OperationObservation;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Rollup\MetricsDelta;
use FreeDSx\Ldap\Server\Metrics\Rollup\MetricsDeltaMessage;
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationRollupCoordinator;
use FreeDSx\Ldap\Server\Process\ChildChannel;
use PHPUnit\Framework\TestCase;

final class OperationRollupCoordinatorTest extends TestCase
{
    private InMemoryMetricsRecorder $childRecorder;

    private InMemoryMetricsRecorder $parentRecorder;

    private OperationRollupCoordinator $child;

    private OperationRollupCoordinator $parent;

    protected function setUp(): void
    {
        if (str_starts_with(strtoupper(PHP_OS), 'WIN')) {
            self::markTestSkipped('The rollup uses a UNIX socket pair, unavailable on Windows; it is Linux/PCNTL-only.');
        }

        $this->childRecorder = new InMemoryMetricsRecorder();
        $this->parentRecorder = new InMemoryMetricsRecorder();
        $this->child = new OperationRollupCoordinator($this->childRecorder);
        $this->parent = new OperationRollupCoordinator($this->parentRecorder);
    }

    public function test_a_sub_threshold_flush_defers_the_send_until_finish(): void
    {
        $channel = $this->child->openChannel();
        $this->child->enterChild($channel);

        $this->childRecorder->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.5,
            ResultCode::SUCCESS,
        ));
        $this->child->flush();
        $this->parent->collect($channel);

        self::assertSame(
            [],
            $this->parentRecorder->snapshot()->operations->counts,
        );

        $this->child->finish();
        $this->parent->collect($channel);

        self::assertSame(
            ['search' => 1],
            $this->parentRecorder->snapshot()->operations->counts,
        );
    }

    public function test_reaching_the_op_batch_threshold_sends_without_finish(): void
    {
        $channel = $this->child->openChannel();
        $this->child->enterChild($channel);

        // FLUSH_OPS = 256; the 256th flush crosses the batch and sends the accumulated delta.
        for ($i = 0; $i < 256; $i++) {
            $this->childRecorder->operationObserved(new OperationObservation(
                OperationType::Search,
                true,
                0.1,
                ResultCode::SUCCESS,
            ));
            $this->child->flush();
        }
        $this->parent->collect($channel);

        self::assertSame(
            ['search' => 256],
            $this->parentRecorder->snapshot()->operations->counts,
        );
    }

    public function test_the_time_interval_triggers_a_send_between_ops(): void
    {
        $channel = $this->child->openChannel();
        $this->child->enterChild($channel);

        $this->childRecorder->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.1,
            ResultCode::SUCCESS,
        ));
        $this->child->flush();

        // Past FLUSH_INTERVAL_SECONDS (0.1s), the next flush sends even though the op count is far below the batch.
        usleep(120000);

        $this->childRecorder->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.1,
            ResultCode::SUCCESS,
        ));
        $this->child->flush();
        $this->parent->collect($channel);

        self::assertSame(
            ['search' => 2],
            $this->parentRecorder->snapshot()->operations->counts,
        );
    }

    public function test_entering_a_child_clears_operations_inherited_from_the_parent(): void
    {
        $channel = $this->child->openChannel();

        $this->childRecorder->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.5,
            ResultCode::SUCCESS,
        ));
        $this->child->enterChild($channel);
        $this->child->flush();
        $this->parent->collect($channel);

        self::assertSame(
            [],
            $this->parentRecorder->snapshot()->operations->counts,
        );
    }

    public function test_operations_while_the_parent_is_not_reading_merge_into_the_next_frame(): void
    {
        $channel = $this->child->openChannel();
        $this->child->enterChild($channel);
        $this->fill($channel);

        for ($i = 0; $i < 3; $i++) {
            $this->childRecorder->operationObserved(new OperationObservation(
                OperationType::Search,
                true,
                0.1,
                ResultCode::SUCCESS,
            ));
            usleep(120000);
            $this->child->flush();
        }
        $this->parent->collect($channel);
        $this->child->finish();
        $this->parent->collect($channel);

        self::assertSame(
            ['search' => 3],
            $this->parentRecorder->snapshot()->operations->counts,
        );
    }

    public function test_finishing_while_the_parent_is_not_reading_gives_up_rather_than_hanging(): void
    {
        $channel = $this->child->openChannel();
        $this->child->enterChild($channel);
        $this->fill($channel);
        $startedAt = microtime(true);

        $this->child->finish();

        self::assertLessThan(
            2.0,
            microtime(true) - $startedAt,
        );
    }

    public function test_finishing_flushes_remaining_operations_and_signals_eof(): void
    {
        $channel = $this->child->openChannel();
        $this->child->enterChild($channel);

        $this->childRecorder->operationObserved(new OperationObservation(
            OperationType::Bind,
            true,
            0.1,
            ResultCode::SUCCESS,
        ));
        $this->child->finish();
        $this->parent->collect($channel);

        self::assertSame(
            ['bind' => 1],
            $this->parentRecorder->snapshot()->operations->counts,
        );
        self::assertSame(
            [],
            $channel->receive(),
        );
    }

    private function fill(ChildChannel $channel): void
    {
        while ($channel->send(new MetricsDeltaMessage(new MetricsDelta()))) {
        }
    }
}
