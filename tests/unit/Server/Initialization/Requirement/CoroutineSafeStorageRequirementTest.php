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
use FreeDSx\Ldap\Server\Config\Storage\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Initialization\Requirement\CoroutineSafeStorageRequirement;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class CoroutineSafeStorageRequirementTest extends TestCase
{
    private ServerOptions $options;

    private CoroutineSafeStorageRequirement $subject;

    protected function setUp(): void
    {
        $this->options = TestServerOptions::sqlite()->setRunnerConfig(RunnerConfig::forSwoole(1));
        $this->subject = new CoroutineSafeStorageRequirement($this->options);
    }

    public function test_an_in_memory_sqlite_database_is_refused_under_swoole(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('an in-memory SQLite database is not supported');

        $this->subject->assertMet();
    }

    public function test_a_sqlite_file_is_met_under_swoole(): void
    {
        $this->options->setStorageConfig(PdoConfig::forSqlite('/var/lib/ldap.sqlite'));

        $this->expectNotToPerformAssertions();

        $this->subject->assertMet();
    }

    public function test_in_memory_storage_is_met_under_swoole(): void
    {
        $this->options->setStorageConfig(new InMemoryStorageConfig());

        $this->expectNotToPerformAssertions();

        $this->subject->assertMet();
    }

    public function test_an_in_memory_sqlite_database_is_left_to_the_forking_runner_check(): void
    {
        $this->options->setRunnerConfig(RunnerConfig::forPcntl());

        $this->expectNotToPerformAssertions();

        $this->subject->assertMet();
    }
}
