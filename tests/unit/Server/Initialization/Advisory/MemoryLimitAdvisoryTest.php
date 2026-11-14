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
use FreeDSx\Ldap\Server\Initialization\Advisory\MemoryLimitAdvisory;
use FreeDSx\Ldap\Server\Initialization\InitializationWarning;
use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;
use FreeDSx\Ldap\Server\Resources\MemoryLimit;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class MemoryLimitAdvisoryTest extends TestCase
{
    private const HELD_REQUEST_SIZE = 536_870_912;

    private ServerOptions $options;

    protected function setUp(): void
    {
        $this->options = TestServerOptions::defaults()->setRunnerConfig(RunnerConfig::forSwoole(1));
    }

    public function test_it_warns_when_swoole_can_need_more_than_its_memory_limit(): void
    {
        self::assertEquals(
            [
                InitializationWarning::concurrencyLimited(
                    ConcurrencyLimitReason::MemoryLimit,
                    [
                        'memory_limit' => 134_217_728,
                        'max_connections' => 1_024,
                        'max_held_request_size' => self::HELD_REQUEST_SIZE,
                    ],
                ),
            ],
            $this->advisoryFor(new MemoryLimit(134_217_728))->warnings(),
        );
    }

    public function test_it_does_not_warn_when_swoole_has_memory_for_every_connection_and_what_it_holds(): void
    {
        self::assertSame(
            [],
            $this->advisoryFor(new MemoryLimit(1_073_741_824))->warnings(),
        );
    }

    public function test_it_does_not_warn_for_the_forking_runner(): void
    {
        $this->options->setRunnerConfig(RunnerConfig::forPcntl());

        self::assertSame(
            [],
            $this->advisoryFor(new MemoryLimit(134_217_728))->warnings(),
        );
    }

    private function advisoryFor(MemoryLimit $memoryLimit): MemoryLimitAdvisory
    {
        return new MemoryLimitAdvisory(
            $this->options,
            $memoryLimit,
            self::HELD_REQUEST_SIZE,
        );
    }
}
