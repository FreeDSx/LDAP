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

namespace Tests\Unit\FreeDSx\Ldap\Server\Initialization\Requirement;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\Server\Initialization\Requirement\RunnerExtensionsRequirement;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class RunnerExtensionsRequirementTest extends TestCase
{
    use RequiresExtensionsTrait;

    private ServerOptions $options;

    private RunnerExtensionsRequirement $subject;

    protected function setUp(): void
    {
        $this->options = TestServerOptions::defaults();
        $this->subject = new RunnerExtensionsRequirement($this->options);
    }

    public function test_the_swoole_runner_is_refused_without_the_swoole_extension(): void
    {
        $this->requireMissingExtension('swoole');
        $this->options->setRunnerConfig(RunnerConfig::forSwoole(1));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The Swoole extension is required to use the Swoole runner.');

        $this->subject->assertMet();
    }

    public function test_the_pcntl_runner_is_refused_without_process_control(): void
    {
        $this->requireMissingExtension(
            'pcntl',
            'posix',
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The pcntl and posix extensions are required to fork and manage child processes');

        $this->subject->assertMet();
    }

    public function test_the_swoole_runner_is_met_with_the_swoole_extension(): void
    {
        $this->requireSwoole();
        $this->options->setRunnerConfig(RunnerConfig::forSwoole(1));

        $this->expectNotToPerformAssertions();

        $this->subject->assertMet();
    }

    public function test_the_pcntl_runner_is_met_with_process_control(): void
    {
        $this->requirePcntl();
        $this->requirePosix();

        $this->expectNotToPerformAssertions();

        $this->subject->assertMet();
    }
}
