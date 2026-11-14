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
use FreeDSx\Ldap\Server\Config\Storage\StorageConfigInterface;
use FreeDSx\Ldap\Server\Initialization\Requirement\ForkSafeStorageRequirement;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class ForkSafeStorageRequirementTest extends TestCase
{
    private ServerOptions $options;

    private ForkSafeStorageRequirement $subject;

    protected function setUp(): void
    {
        $this->options = TestServerOptions::defaults()->setRunnerConfig(RunnerConfig::forPcntl());
        $this->subject = new ForkSafeStorageRequirement($this->options);
    }

    /**
     * @return array<string, array{StorageConfigInterface}>
     */
    public static function unsharedStorageProvider(): array
    {
        return [
            'in-memory' => [new InMemoryStorageConfig()],
            'sqlite in-memory' => [PdoConfig::forSqlite(':memory:')],
        ];
    }

    #[DataProvider('unsharedStorageProvider')]
    public function test_storage_one_process_holds_is_refused_under_the_forking_runner(
        StorageConfigInterface $storageConfig,
    ): void {
        $this->options->setStorageConfig($storageConfig);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The Pcntl runner forks per connection');

        $this->subject->assertMet();
    }

    public function test_storage_every_process_shares_is_met_under_the_forking_runner(): void
    {
        $this->options->setStorageConfig(PdoConfig::forSqlite('/var/lib/ldap.sqlite'));

        $this->expectNotToPerformAssertions();

        $this->subject->assertMet();
    }

    public function test_storage_one_process_holds_is_met_under_swoole(): void
    {
        $this->options->setRunnerConfig(RunnerConfig::forSwoole(1));

        $this->expectNotToPerformAssertions();

        $this->subject->assertMet();
    }
}
