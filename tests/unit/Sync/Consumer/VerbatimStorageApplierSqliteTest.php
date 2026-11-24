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

namespace Tests\Unit\FreeDSx\Ldap\Sync\Consumer;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\DeferredLinksInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Sync\Consumer\ReplicaMoves;
use FreeDSx\Ldap\Sync\Consumer\VerbatimStorageApplier;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use Tests\Support\FreeDSx\Ldap\Sync\VerbatimStorageApplierTests;

final class VerbatimStorageApplierSqliteTest extends TestCase
{
    use ServerContainerTrait;
    use VerbatimStorageApplierTests;

    protected function setUp(): void
    {
        $lister = $this->fromContainer(ListEntryInterface::class);
        $this->reader = $this->fromContainer(ReadEntryInterface::class);
        $this->writer = $this->fromContainer(WriteEntryInterface::class);
        $this->subject = new VerbatimStorageApplier(
            $lister,
            $this->writer,
            $this->reader,
            $this->fromContainer(TransactionalWriteInterface::class),
            new ReplicaMoves(
                $this->reader,
                $lister,
                $this->writer,
            ),
            $this->fromContainer(DeferredLinksInterface::class),
        );
    }

    public function test_an_entry_moved_aside_for_a_new_one_keeps_its_group_membership(): void
    {
        $this->writer->store($this->entry('cn=olga,dc=example,dc=com', self::UUID_A));
        $this->writer->store(new Entry(
            'cn=crew,dc=example,dc=com',
            new Attribute('cn', 'crew'),
            new Attribute('member', 'cn=olga,dc=example,dc=com'),
            new Attribute('entryUUID', self::UUID_C),
        ));

        $this->applyAdd('cn=olga,dc=example,dc=com', self::UUID_B);
        $this->applyMove('cn=olga-renamed,dc=example,dc=com', self::UUID_A);

        self::assertSame(
            ['cn=olga-renamed,dc=example,dc=com'],
            $this->reader->find((new Dn('cn=crew,dc=example,dc=com'))->normalize())?->get('member')?->getValues(),
        );
    }

    public function test_a_thousand_entries_trading_dns_in_one_window_are_all_placed_at_once(): void
    {
        for ($pair = 0; $pair <= 500; $pair++) {
            $this->writer->store($this->entry("cn=x{$pair},dc=example,dc=com", $this->uuidFor("x{$pair}")));
            $this->writer->store($this->entry("cn=y{$pair},dc=example,dc=com", $this->uuidFor("y{$pair}")));
        }

        for ($pair = 0; $pair <= 500; $pair++) {
            $this->applyMove("cn=y{$pair},dc=example,dc=com", $this->uuidFor("x{$pair}"));
            $this->applyMove("cn=x{$pair},dc=example,dc=com", $this->uuidFor("y{$pair}"));
        }
        $this->subject->settle();
        $this->subject->settle();

        self::assertSame(
            $this->uuidFor('x0'),
            $this->value('cn=y0,dc=example,dc=com', 'entryUUID'),
        );
        self::assertSame(
            $this->uuidFor('y500'),
            $this->value('cn=x500,dc=example,dc=com', 'entryUUID'),
        );
    }

    public function test_a_refresh_links_the_values_held_back_for_more_groups_than_one_batch_takes(): void
    {
        $groups = [];

        for ($group = 0; $group <= 500; $group++) {
            $groups[] = $this->group(
                "cn=g{$group},dc=example,dc=com",
                $this->uuidFor("g{$group}"),
                'cn=alice,dc=example,dc=com',
            );
        }

        $this->refresh(
            $this->entry('cn=alice,dc=example,dc=com', self::UUID_A),
            ...$groups,
        );

        self::assertSame(
            ['cn=alice,dc=example,dc=com'],
            $this->members('cn=g500,dc=example,dc=com'),
        );
    }

    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::replicaOn(PdoConfig::forSqlite(':memory:'));
    }
}
