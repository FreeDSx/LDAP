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
use Generator;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\TestResettableEntryStorage;
use Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\TestRowLockableEntryStorage;
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
            (function (): Generator {
                yield from [];

                return null;
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

    public function test_rename_subtree_routes_through_queue_to_writes(): void
    {
        $from = new Dn('ou=people,dc=example,dc=com');
        $to = new Dn('ou=staff,dc=example,dc=com');

        $this->writes
            ->expects(self::once())
            ->method('renameSubtree')
            ->with($from, $to);
        $this->reads
            ->expects(self::never())
            ->method('renameSubtree');

        $this->subject->renameSubtree(
            $from,
            $to,
        );

        self::assertSame(
            1,
            $this->queue->ranCount,
        );
    }

    public function test_atomic_routes_through_queue_to_writes(): void
    {
        $callable = function (): void {
            $this->subject->remove(new Dn('cn=foo,dc=example,dc=com'));
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

    public function test_reads_route_to_the_write_storage_inside_an_atomic_block(): void
    {
        $dn = new Dn('cn=alice,dc=example,dc=com');
        $entry = new Entry($dn, new Attribute('cn', 'Alice'));

        $this->passAtomicThrough();
        $this->writes
            ->expects(self::once())
            ->method('find')
            ->with($dn)
            ->willReturn($entry);
        $this->reads
            ->expects(self::never())
            ->method('find');

        $found = null;
        $this->subject->atomic(function () use (&$found, $dn): void {
            $found = $this->subject->find($dn);
        });

        self::assertSame(
            $entry,
            $found,
        );
    }

    public function test_writes_bypass_the_queue_inside_an_atomic_block(): void
    {
        $entry = new Entry(
            new Dn('cn=carol,dc=example,dc=com'),
            new Attribute('cn', 'Carol'),
        );

        $this->passAtomicThrough();
        $this->writes
            ->expects(self::once())
            ->method('store')
            ->with($entry);

        $this->subject->atomic(function () use ($entry): void {
            $this->subject->store($entry);
        });

        // Only the block itself was queued; queueing the store would block the writer on its own reply.
        self::assertSame(
            1,
            $this->queue->ranCount,
        );
    }

    public function test_a_nested_atomic_block_does_not_queue_again(): void
    {
        $opened = 0;
        $this->writes
            ->method('atomic')
            ->willReturnCallback(static function (callable $operation) use (&$opened): void {
                $opened++;
                $operation();
            });

        $this->subject->atomic(function (): void {
            $this->subject->atomic(static function (): void {});
        });

        self::assertSame(
            2,
            $opened,
        );
        self::assertSame(
            1,
            $this->queue->ranCount,
        );
    }

    public function test_reads_return_to_the_read_storage_after_the_block(): void
    {
        $dn = new Dn('cn=alice,dc=example,dc=com');

        $this->passAtomicThrough();
        $this->reads
            ->expects(self::once())
            ->method('find')
            ->with($dn);

        $this->subject->atomic(static function (): void {});
        $this->subject->find($dn);
    }

    public function test_the_scope_is_released_when_the_operation_throws(): void
    {
        $dn = new Dn('cn=alice,dc=example,dc=com');

        $this->passAtomicThrough();
        $this->reads
            ->expects(self::once())
            ->method('find')
            ->with($dn);

        $caught = null;
        try {
            $this->subject->atomic(static function (): void {
                throw new RuntimeException('boom');
            });
        } catch (RuntimeException $e) {
            $caught = $e;
        }

        $this->subject->find($dn);

        self::assertSame(
            'boom',
            $caught?->getMessage(),
        );
    }

    public function test_lock_for_write_routes_to_writes(): void
    {
        $dn = new Dn('cn=alice,dc=example,dc=com');
        $writes = $this->createMock(TestRowLockableEntryStorage::class);

        $writes
            ->expects(self::once())
            ->method('lockForWrite')
            ->with($dn);

        $subject = new WriteSerializingStorage(
            reads: $this->reads,
            writes: $writes,
            queue: $this->queue,
        );

        $subject->lockForWrite($dn);
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

    /**
     * Stands in for a real transaction, which invokes the operation rather than merely accepting it.
     */
    private function passAtomicThrough(): void
    {
        $this->writes
            ->method('atomic')
            ->willReturnCallback(static function (callable $operation): void {
                $operation();
            });
    }
}
