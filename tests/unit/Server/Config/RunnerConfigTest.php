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

namespace Tests\Unit\FreeDSx\Ldap\Server\Config;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use PHPUnit\Framework\TestCase;

final class RunnerConfigTest extends TestCase
{
    private RunnerConfig $subject;

    protected function setUp(): void
    {
        $this->subject = new RunnerConfig();
    }

    public function test_it_defaults_to_forking_on_a_single_worker(): void
    {
        self::assertSame(
            RunnerMode::Pcntl,
            $this->subject->getMode(),
        );
        self::assertSame(
            1,
            $this->subject->getWorkers(),
        );
    }

    public function test_it_takes_the_mode_and_workers_from_the_constructor(): void
    {
        $subject = new RunnerConfig(
            RunnerMode::Swoole,
            4,
        );

        self::assertSame(
            RunnerMode::Swoole,
            $subject->getMode(),
        );
        self::assertSame(
            4,
            $subject->getWorkers(),
        );
    }

    public function test_it_builds_a_coroutine_runner_that_uses_every_cpu_by_default(): void
    {
        $subject = RunnerConfig::forSwoole();

        self::assertSame(
            RunnerMode::Swoole,
            $subject->getMode(),
        );
        self::assertSame(
            RunnerConfig::AUTO_DETECT_WORKERS,
            $subject->getWorkers(),
        );
    }

    public function test_it_builds_a_coroutine_runner_with_a_fixed_worker_count(): void
    {
        $subject = RunnerConfig::forSwoole(4);

        self::assertSame(
            RunnerMode::Swoole,
            $subject->getMode(),
        );
        self::assertSame(
            4,
            $subject->getWorkers(),
        );
    }

    public function test_it_builds_a_forking_runner(): void
    {
        $subject = RunnerConfig::forPcntl();

        self::assertSame(
            RunnerMode::Pcntl,
            $subject->getMode(),
        );
        self::assertFalse($subject->isSingleProcess());
    }

    public function test_the_forking_runner_is_never_a_single_process(): void
    {
        self::assertFalse($this->subject->isSingleProcess());
    }

    public function test_one_coroutine_worker_is_a_single_process(): void
    {
        self::assertTrue((new RunnerConfig(RunnerMode::Swoole))->isSingleProcess());
    }

    public function test_several_coroutine_workers_are_not_a_single_process(): void
    {
        self::assertFalse(
            (new RunnerConfig(
                RunnerMode::Swoole,
                2,
            ))->isSingleProcess(),
        );
    }

    public function test_auto_detected_workers_are_not_assumed_to_be_a_single_process(): void
    {
        self::assertFalse(
            (new RunnerConfig(
                RunnerMode::Swoole,
                0,
            ))->isSingleProcess(),
        );
    }

    public function test_it_rejects_a_negative_worker_count_from_the_constructor(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new RunnerConfig(
            RunnerMode::Swoole,
            -1,
        );
    }

    public function test_it_rejects_a_negative_worker_count_from_the_setter(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->subject->setWorkers(-1);
    }
}
