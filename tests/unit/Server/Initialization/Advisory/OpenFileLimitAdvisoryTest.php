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
use FreeDSx\Ldap\Server\Initialization\Advisory\OpenFileLimitAdvisory;
use FreeDSx\Ldap\Server\Initialization\InitializationWarning;
use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;
use FreeDSx\Ldap\Server\Resources\OpenFileLimit;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class OpenFileLimitAdvisoryTest extends TestCase
{
    private ServerOptions $options;

    protected function setUp(): void
    {
        $this->options = TestServerOptions::defaults()->setRunnerConfig(RunnerConfig::forSwoole(1));
    }

    public function test_it_warns_when_swoole_reaches_the_open_file_limit_before_the_connection_limit(): void
    {
        self::assertEquals(
            [
                InitializationWarning::concurrencyLimited(
                    ConcurrencyLimitReason::OpenFileLimit,
                    [
                        'open_file_limit' => 1_024,
                        'max_connections' => 1_024,
                        'descriptors_per_client' => 2,
                    ],
                ),
            ],
            $this->advisoryFor(new OpenFileLimit(1_024))->warnings(),
        );
    }

    public function test_it_does_not_warn_when_swoole_has_open_files_for_every_connection(): void
    {
        self::assertSame(
            [],
            $this->advisoryFor(new OpenFileLimit(100_000))->warnings(),
        );
    }

    public function test_it_does_not_warn_without_an_open_file_limit(): void
    {
        self::assertSame(
            [],
            $this->advisoryFor(new OpenFileLimit(null))->warnings(),
        );
    }

    public function test_it_does_not_warn_for_the_forking_runner(): void
    {
        $this->options->setRunnerConfig(RunnerConfig::forPcntl());

        self::assertSame(
            [],
            $this->advisoryFor(new OpenFileLimit(1_024))->warnings(),
        );
    }

    private function advisoryFor(OpenFileLimit $openFileLimit): OpenFileLimitAdvisory
    {
        return new OpenFileLimitAdvisory(
            $this->options,
            $openFileLimit,
            2,
        );
    }
}
