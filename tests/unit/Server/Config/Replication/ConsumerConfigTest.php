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

namespace Tests\Unit\FreeDSx\Ldap\Server\Config\Replication;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Server\Config\Replication\ConsumerConfig;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Sync\Consumer\Checkpoint\InMemoryReplicationCheckpoint;
use FreeDSx\Ldap\Sync\Consumer\Checkpoint\ReplicationCheckpointInterface;
use PHPUnit\Framework\TestCase;

final class ConsumerConfigTest extends TestCase
{
    private ConsumerConfig $subject;

    protected function setUp(): void
    {
        $this->subject = new ConsumerConfig(
            (new ClientOptions())
                ->setServers(['primary.example.com'])
                ->setPort(636)
                ->setUseSsl(true),
        );
    }

    public function test_it_defaults_to_an_in_memory_checkpoint(): void
    {
        self::assertInstanceOf(
            InMemoryReplicationCheckpoint::class,
            $this->subject->getCheckpoint(),
        );
    }

    public function test_it_defaults_to_referring_writes_with_no_filter(): void
    {
        self::assertTrue($this->subject->shouldReferWrites());
        self::assertNull($this->subject->getFilter());
    }

    public function test_it_exposes_the_primary_options(): void
    {
        self::assertSame(
            ['primary.example.com'],
            $this->subject->getPrimary()->getServers(),
        );
    }

    public function test_it_derives_the_primary_referral_urls(): void
    {
        $urls = $this->subject->referralUrls();

        self::assertCount(
            1,
            $urls,
        );
        self::assertSame(
            'primary.example.com',
            $urls[0]->getHost(),
        );
        self::assertSame(
            636,
            $urls[0]->getPort(),
        );
        self::assertTrue($urls[0]->getUseSsl());
    }

    public function test_the_filter_and_write_policy_are_fluent(): void
    {
        $filter = Filters::present('objectClass');

        $result = $this->subject
            ->setFilter($filter)
            ->setReferWrites(false);

        self::assertSame(
            $this->subject,
            $result,
        );
        self::assertSame(
            $filter,
            $this->subject->getFilter(),
        );
        self::assertFalse($this->subject->shouldReferWrites());
    }

    public function test_a_custom_checkpoint_is_used(): void
    {
        $checkpoint = $this->createMock(ReplicationCheckpointInterface::class);

        $config = new ConsumerConfig(
            new ClientOptions(),
            $checkpoint,
        );

        self::assertSame(
            $checkpoint,
            $config->getCheckpoint(),
        );
    }
}
