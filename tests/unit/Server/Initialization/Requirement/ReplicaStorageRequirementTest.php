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

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Config\Replication\ConsumerConfig;
use FreeDSx\Ldap\Server\Config\ReplicationConfig;
use FreeDSx\Ldap\Server\Config\Storage\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Initialization\Requirement\ReplicaStorageRequirement;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class ReplicaStorageRequirementTest extends TestCase
{
    private ServerOptions $options;

    private ReplicaStorageRequirement $subject;

    protected function setUp(): void
    {
        $this->options = TestServerOptions::defaults();
        $this->subject = new ReplicaStorageRequirement($this->options);
    }

    public function test_a_replica_without_pdo_storage_is_refused(): void
    {
        $this->options->setReplicationConfig(ReplicationConfig::forReplica(new ConsumerConfig(new ClientOptions())));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(sprintf(
            'A read-only replica requires PDO storage, but "%s" is configured.',
            InMemoryStorageConfig::class,
        ));

        $this->subject->assertMet();
    }

    public function test_a_replica_on_pdo_storage_is_met(): void
    {
        $this->options
            ->setReplicationConfig(ReplicationConfig::forReplica(new ConsumerConfig(new ClientOptions())))
            ->setStorageConfig(PdoConfig::forSqlite(':memory:'));

        $this->expectNotToPerformAssertions();

        $this->subject->assertMet();
    }

    public function test_a_server_that_is_not_a_replica_is_met_without_pdo_storage(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertMet();
    }
}
