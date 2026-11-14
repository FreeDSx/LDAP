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
use FreeDSx\Ldap\Server\Config\Storage\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Initialization\Advisory\BlockingSqliteAdvisory;
use FreeDSx\Ldap\Server\Initialization\InitializationWarning;
use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

use function defined;

final class BlockingSqliteAdvisoryTest extends TestCase
{
    private ServerOptions $options;

    private BlockingSqliteAdvisory $subject;

    protected function setUp(): void
    {
        $this->options = TestServerOptions::forStorage(PdoConfig::forSqlite('/var/lib/ldap.sqlite'))
            ->setRunnerConfig(RunnerConfig::forSwoole(1));
        $this->subject = new BlockingSqliteAdvisory($this->options);
    }

    public function test_it_warns_when_swoole_was_built_without_the_sqlite_hook(): void
    {
        if (defined('SWOOLE_HOOK_PDO_SQLITE')) {
            self::markTestSkipped('This Swoole build runs SQLite without blocking the worker.');
        }

        self::assertEquals(
            [InitializationWarning::concurrencyLimited(ConcurrencyLimitReason::StorageBlocksWorker)],
            $this->subject->warnings(),
        );
    }

    public function test_it_does_not_warn_for_the_forking_runner(): void
    {
        $this->options->setRunnerConfig(RunnerConfig::forPcntl());

        self::assertSame(
            [],
            $this->subject->warnings(),
        );
    }

    public function test_it_does_not_warn_for_mysql(): void
    {
        $this->options->setStorageConfig(PdoConfig::forMysql(
            'mysql:host=localhost;dbname=ldap',
            'ldap',
            'secret',
        ));

        self::assertSame(
            [],
            $this->subject->warnings(),
        );
    }

    public function test_it_does_not_warn_for_in_memory_storage(): void
    {
        $this->options->setStorageConfig(new InMemoryStorageConfig());

        self::assertSame(
            [],
            $this->subject->warnings(),
        );
    }
}
