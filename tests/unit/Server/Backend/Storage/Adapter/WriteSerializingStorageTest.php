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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriteSerializingStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\TestResettableEntryStorage;
use Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\TestSynchronousWriterQueue;

final class WriteSerializingStorageTest extends TestCase
{
    private EntryStorageInterface&MockObject $reads;

    private EntryStorageInterface&MockObject $writes;

    private TestSynchronousWriterQueue $queue;

    private WriteSerializingStorage $subject;

    protected function setUp(): void
    {
        $this->reads = $this->createMock(EntryStorageInterface::class);
        $this->writes = $this->createMock(EntryStorageInterface::class);
        $this->queue = new TestSynchronousWriterQueue();
        $this->subject = new WriteSerializingStorage(
            reads: $this->reads,
            writes: $this->writes,
            queue: $this->queue,
        );
    }

    public function test_find_routes_to_reads(): void
    {
        $dn = new Dn('cn=alice,dc=example,dc=com');
        $entry = new Entry($dn, new Attribute('cn', 'Alice'));

        $this->reads
            ->expects(self::once())
            ->method('find')
            ->with($dn)
            ->willReturn($entry);
        $this->writes
            ->expects(self::never())
            ->method('find');

        self::assertSame(
            $entry,
            $this->subject->find($dn),
        );
    }

    public function test_exists_routes_to_reads(): void
    {
        $dn = new Dn('cn=bob,dc=example,dc=com');

        $this->reads
            ->expects(self::once())
            ->method('exists')
            ->with($dn)
            ->willReturn(true);
        $this->writes
            ->expects(self::never())
            ->method('exists');

        self::assertTrue($this->subject->exists($dn));
    }

    public function test_has_children_routes_to_reads(): void
    {
        $dn = new Dn('ou=people,dc=example,dc=com');

        $this->reads
            ->expects(self::once())
            ->method('hasChildren')
            ->with($dn)
            ->willReturn(true);
        $this->writes
            ->expects(self::never())
            ->method('hasChildren');

        self::assertTrue($this->subject->hasChildren($dn));
    }

    public function test_list_routes_to_reads(): void
    {
        $options = StorageListOptions::matchAll(
            baseDn: new Dn('dc=example,dc=com'),
            subtree: true,
        );
        $stream = new EntryStream(
            (function () {
                yield from [];
            })(),
        );

        $this->reads
            ->expects(self::once())
            ->method('list')
            ->with($options)
            ->willReturn($stream);
        $this->writes
            ->expects(self::never())
            ->method('list');

        self::assertSame(
            $stream,
            $this->subject->list($options),
        );
    }

    public function test_store_routes_through_queue_to_writes(): void
    {
        $entry = new Entry(
            new Dn('cn=carol,dc=example,dc=com'),
            new Attribute('cn', 'Carol'),
        );

        $this->writes
            ->expects(self::once())
            ->method('store')
            ->with($entry);
        $this->reads
            ->expects(self::never())
            ->method('store');

        $this->subject->store($entry);

        self::assertSame(
            1,
            $this->queue->ranCount,
        );
    }

    public function test_remove_routes_through_queue_to_writes(): void
    {
        $dn = new Dn('cn=carol,dc=example,dc=com');

        $this->writes
            ->expects(self::once())
            ->method('remove')
            ->with($dn);
        $this->reads
            ->expects(self::never())
            ->method('remove');

        $this->subject->remove($dn);

        self::assertSame(
            1,
            $this->queue->ranCount,
        );
    }

    public function test_atomic_routes_through_queue_to_writes(): void
    {
        $callable = static function (EntryStorageInterface $s): void {
            $s->remove(new Dn('cn=foo,dc=example,dc=com'));
        };

        $this->writes
            ->expects(self::once())
            ->method('atomic')
            ->with($callable);
        $this->reads
            ->expects(self::never())
            ->method('atomic');

        $this->subject->atomic($callable);
    }

    public function test_write_exceptions_propagate(): void
    {
        $entry = new Entry(
            new Dn('cn=carol,dc=example,dc=com'),
            new Attribute('cn', 'Carol'),
        );

        $this->writes
            ->method('store')
            ->willThrowException(new RuntimeException('boom'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('boom');

        $this->subject->store($entry);
    }

    public function test_reset_resets_both_storages_when_resettable(): void
    {
        $reads = $this->createMock(TestResettableEntryStorage::class);
        $writes = $this->createMock(TestResettableEntryStorage::class);

        $reads->expects(self::once())->method('reset');
        $writes->expects(self::once())->method('reset');

        $subject = new WriteSerializingStorage(
            reads: $reads,
            writes: $writes,
            queue: $this->queue,
        );

        $subject->reset();
    }

    public function test_reset_skips_non_resettable_storages(): void
    {
        $this->reads->expects(self::never())->method(self::anything());
        $this->writes->expects(self::never())->method(self::anything());

        $this->subject->reset();
    }
}
