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

namespace Tests\Unit\FreeDSx\Ldap\Server\Initialization\Advisory;

use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\Server\Initialization\Advisory\WorkerClampAdvisory;
use FreeDSx\Ldap\Server\Initialization\InitializationWarning;
use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class WorkerClampAdvisoryTest extends TestCase
{
    private ServerOptions $options;

    protected function setUp(): void
    {
        $this->options = TestServerOptions::defaults()->setRunnerConfig(RunnerConfig::forSwoole(4));
    }

    public function test_it_warns_when_several_workers_are_clamped_to_one_for_state_they_cannot_share(): void
    {
        self::assertEquals(
            [
                InitializationWarning::concurrencyLimited(
                    ConcurrencyLimitReason::StorageNotShareable,
                    ['requested_workers' => 4],
                ),
            ],
            $this->advisoryFor(false)->warnings(),
        );
    }

    public function test_it_does_not_warn_when_the_workers_can_share_the_server(): void
    {
        self::assertSame(
            [],
            $this->advisoryFor(true)->warnings(),
        );
    }

    public function test_it_does_not_warn_for_one_worker(): void
    {
        $this->options->setRunnerConfig(RunnerConfig::forSwoole(1));

        self::assertSame(
            [],
            $this->advisoryFor(false)->warnings(),
        );
    }

    public function test_it_does_not_warn_for_the_forking_runner(): void
    {
        $this->options->setRunnerConfig(RunnerConfig::forPcntl());

        self::assertSame(
            [],
            $this->advisoryFor(false)->warnings(),
        );
    }

    private function advisoryFor(bool $supportsMultipleWorkers): WorkerClampAdvisory
    {
        return new WorkerClampAdvisory(
            $this->options,
            $supportsMultipleWorkers,
        );
    }
}
