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

namespace Tests\Unit\FreeDSx\Ldap\Server\ServerRunner\Swoole;

use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\WorkerLimit;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class WorkerLimitTest extends TestCase
{
    private ServerOptions $options;

    protected function setUp(): void
    {
        $this->options = TestServerOptions::defaults()->setRunnerConfig(RunnerConfig::forSwoole(4));
    }

    public function test_the_forking_runner_accepts_on_one_process_without_a_limit(): void
    {
        $this->options->setRunnerConfig(RunnerConfig::forPcntl());

        self::assertSame(
            [1, null],
            $this->workersAndReason(true),
        );
    }

    public function test_one_configured_worker_is_not_limited(): void
    {
        $this->options->setRunnerConfig(RunnerConfig::forSwoole(1));

        self::assertSame(
            [1, null],
            $this->workersAndReason(false),
        );
    }

    public function test_several_workers_are_kept_when_the_backend_and_the_listener_can_be_shared(): void
    {
        self::assertSame(
            [4, null],
            $this->workersAndReason(true),
        );
    }

    public function test_a_backend_that_cannot_be_shared_limits_the_workers_to_one(): void
    {
        self::assertSame(
            [1, ConcurrencyLimitReason::StorageNotShareable],
            $this->workersAndReason(false),
        );
    }

    public function test_a_unix_socket_limits_the_workers_to_one(): void
    {
        $this->options->getNetworkConfig()->setTransport('unix');

        self::assertSame(
            [1, ConcurrencyLimitReason::UnixSocket],
            $this->workersAndReason(true),
        );
    }

    public function test_the_backend_is_named_when_it_and_a_unix_socket_both_limit_the_workers(): void
    {
        $this->options->getNetworkConfig()->setTransport('unix');

        self::assertSame(
            [1, ConcurrencyLimitReason::StorageNotShareable],
            $this->workersAndReason(false),
        );
    }

    public function test_it_reports_the_configured_count_even_when_limited(): void
    {
        self::assertSame(
            4,
            (new WorkerLimit(
                $this->options,
                false,
            ))->requested(),
        );
    }

    /**
     * @return array{int, ?ConcurrencyLimitReason}
     */
    private function workersAndReason(bool $backendSupportsMultipleWorkers): array
    {
        $limit = new WorkerLimit(
            $this->options,
            $backendSupportsMultipleWorkers,
        );

        return [
            $limit->workers(),
            $limit->reason(),
        ];
    }
}
