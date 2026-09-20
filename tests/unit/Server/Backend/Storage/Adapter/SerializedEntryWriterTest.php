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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer\EntryWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\SerializedEntryWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\Backend\Storage\TestSynchronousWriterQueue;

final class SerializedEntryWriterTest extends TestCase
{
    private EntryWriter&MockObject $writes;

    private TransactionalWriteInterface&MockObject $transaction;

    private TestSynchronousWriterQueue $queue;

    private SerializedEntryWriter $subject;

    protected function setUp(): void
    {
        $this->writes = $this->createMock(EntryWriter::class);
        $this->transaction = $this->createMock(TransactionalWriteInterface::class);
        $this->queue = new TestSynchronousWriterQueue();
        $this->subject = new SerializedEntryWriter(
            $this->writes,
            $this->transaction,
            $this->queue,
        );
    }

    public function test_insert_runs_through_the_queue(): void
    {
        $entry = new Entry(
            new Dn('cn=carol,dc=example,dc=com'),
            new Attribute('cn', 'Carol'),
        );

        $this->writes
            ->expects(self::once())
            ->method('insert')
            ->with($entry);

        $this->subject->insert($entry);

        self::assertSame(
            1,
            $this->queue->ranCount,
        );
    }

    public function test_store_runs_through_the_queue(): void
    {
        $entry = new Entry(
            new Dn('cn=carol,dc=example,dc=com'),
            new Attribute('cn', 'Carol'),
        );

        $this->writes
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

        $this->writes
            ->expects(self::once())
            ->method('remove')
            ->with($dn);

        $this->subject->remove($dn);

        self::assertSame(
            1,
            $this->queue->ranCount,
        );
    }

    public function test_remove_all_runs_through_the_queue(): void
    {
        $dns = [new Dn('cn=carol,dc=example,dc=com')];

        $this->writes
            ->expects(self::once())
            ->method('removeAll')
            ->with($dns);

        $this->subject->removeAll($dns);

        self::assertSame(
            1,
            $this->queue->ranCount,
        );
    }

    public function test_rename_subtree_runs_through_the_queue(): void
    {
        $from = new Dn('ou=people,dc=example,dc=com');
        $to = new Dn('ou=staff,dc=example,dc=com');

        $this->writes
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

        $this->transaction
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
        $this->transaction
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

    public function test_lock_for_write_delegates_without_queueing(): void
    {
        $dn = new Dn('cn=alice,dc=example,dc=com');

        $this->writes
            ->expects(self::once())
            ->method('lockForWrite')
            ->with($dn);

        $this->subject->lockForWrite($dn);

        self::assertSame(
            0,
            $this->queue->ranCount,
        );
    }

    public function test_lock_for_reference_delegates_without_queueing(): void
    {
        $dn = new Dn('cn=alice,dc=example,dc=com');

        $this->writes
            ->expects(self::once())
            ->method('lockForReference')
            ->with($dn)
            ->willReturn(true);

        self::assertTrue($this->subject->lockForReference($dn));
        self::assertSame(
            0,
            $this->queue->ranCount,
        );
    }

    public function test_draining_releases_the_queue(): void
    {
        $this->subject->drainWrites();

        self::assertSame(
            1,
            $this->queue->drainedCount,
        );
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

    /**
     * Stands in for a real transaction, which invokes the operation rather than merely accepting it.
     */
    private function passAtomicThrough(): void
    {
        $this->transaction
            ->method('atomic')
            ->willReturnCallback(static function (callable $operation): void {
                $operation();
            });
    }
}
