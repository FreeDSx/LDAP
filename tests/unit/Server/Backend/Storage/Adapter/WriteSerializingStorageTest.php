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
    private EntryStorageInterface&MockObject $storage;

    private TestSynchronousWriterQueue $queue;

    private WriteSerializingStorage $subject;

    protected function setUp(): void
    {
        $this->storage = $this->createMock(EntryStorageInterface::class);
        $this->queue = new TestSynchronousWriterQueue();
        $this->subject = new WriteSerializingStorage(
            $this->storage,
            $this->queue,
        );
    }

    public function test_find_runs_in_place(): void
    {
        $dn = new Dn('cn=alice,dc=example,dc=com');
        $entry = new Entry($dn, new Attribute('cn', 'Alice'));

        $this->storage
            ->expects(self::once())
            ->method('find')
            ->with($dn)
            ->willReturn($entry);

        self::assertSame(
            $entry,
            $this->subject->find($dn),
        );
        self::assertSame(
            0,
            $this->queue->ranCount,
        );
    }

    public function test_exists_runs_in_place(): void
    {
        $dn = new Dn('cn=bob,dc=example,dc=com');

        $this->storage
            ->expects(self::once())
            ->method('exists')
            ->with($dn)
            ->willReturn(true);

        self::assertTrue($this->subject->exists($dn));
        self::assertSame(
            0,
            $this->queue->ranCount,
        );
    }

    public function test_has_children_runs_in_place(): void
    {
        $dn = new Dn('ou=people,dc=example,dc=com');

        $this->storage
            ->expects(self::once())
            ->method('hasChildren')
            ->with($dn)
            ->willReturn(true);

        self::assertTrue($this->subject->hasChildren($dn));
        self::assertSame(
            0,
            $this->queue->ranCount,
        );
    }

    public function test_list_runs_in_place(): void
    {
        $options = StorageListOptions::matchAll(
            baseDn: new Dn('dc=example,dc=com'),
            subtree: true,
        );
        $stream = EntryStream::of(
            (function (): Generator {
                yield from [];

                return null;
            })(),
        );

        $this->storage
            ->expects(self::once())
            ->method('list')
            ->with($options)
            ->willReturn($stream);

        self::assertSame(
            $stream,
            $this->subject->list($options),
        );
        self::assertSame(
            0,
            $this->queue->ranCount,
        );
    }

    public function test_store_runs_through_the_queue(): void
    {
        $entry = new Entry(
            new Dn('cn=carol,dc=example,dc=com'),
            new Attribute('cn', 'Carol'),
        );

        $this->storage
            ->expects(self::once())
            ->method('store')
            ->with($entry);

        $this->subject->store($entry);

        self::assertSame(
            1,
            $this->queue->ranCount,
        );
    }

    public function test_remove_runs_through_the_queue(): void
    {
        $dn = new Dn('cn=carol,dc=example,dc=com');

        $this->storage
            ->expects(self::once())
            ->method('remove')
            ->with($dn);

        $this->subject->remove($dn);

        self::assertSame(
            1,
            $this->queue->ranCount,
        );
    }

    public function test_rename_subtree_runs_through_the_queue(): void
    {
        $from = new Dn('ou=people,dc=example,dc=com');
        $to = new Dn('ou=staff,dc=example,dc=com');

        $this->storage
            ->expects(self::once())
            ->method('renameSubtree')
            ->with($from, $to);

        $this->subject->renameSubtree(
            $from,
            $to,
        );

        self::assertSame(
            1,
            $this->queue->ranCount,
        );
    }

    public function test_atomic_runs_through_the_queue(): void
    {
        $callable = static function (): void {};

        $this->storage
            ->expects(self::once())
            ->method('atomic')
            ->with($callable);

        $this->subject->atomic($callable);

        self::assertSame(
            1,
            $this->queue->ranCount,
        );
    }

    public function test_writes_bypass_the_queue_inside_an_atomic_block(): void
    {
        $entry = new Entry(
            new Dn('cn=carol,dc=example,dc=com'),
            new Attribute('cn', 'Carol'),
        );

        $this->passAtomicThrough();
        $this->storage
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
        $this->storage
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

    public function test_lock_for_write_delegates_to_the_storage(): void
    {
        $dn = new Dn('cn=alice,dc=example,dc=com');
        $storage = $this->createMock(TestRowLockableEntryStorage::class);

        $storage
            ->expects(self::once())
            ->method('lockForWrite')
            ->with($dn);

        $subject = new WriteSerializingStorage(
            $storage,
            $this->queue,
        );

        $subject->lockForWrite($dn);
    }

    public function test_write_exceptions_propagate(): void
    {
        $entry = new Entry(
            new Dn('cn=carol,dc=example,dc=com'),
            new Attribute('cn', 'Carol'),
        );

        $this->storage
            ->method('store')
            ->willThrowException(new RuntimeException('boom'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('boom');

        $this->subject->store($entry);
    }

    public function test_reset_resets_a_resettable_storage(): void
    {
        $storage = $this->createMock(TestResettableEntryStorage::class);

        $storage
            ->expects(self::once())
            ->method('reset');

        $subject = new WriteSerializingStorage(
            $storage,
            $this->queue,
        );

        $subject->reset();
    }

    public function test_reset_skips_a_non_resettable_storage(): void
    {
        $this->storage
            ->expects(self::never())
            ->method(self::anything());

        $this->subject->reset();
    }

    /**
     * Stands in for a real transaction, which invokes the operation rather than merely accepting it.
     */
    private function passAtomicThrough(): void
    {
        $this->storage
            ->method('atomic')
            ->willReturnCallback(static function (callable $operation): void {
                $operation();
            });
    }
}
