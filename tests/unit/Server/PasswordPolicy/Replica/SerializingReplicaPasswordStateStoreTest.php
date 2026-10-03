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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy\Replica;

use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordState;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\SerializingReplicaPasswordStateStore;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Backend\Storage\RecordingWriterQueue;

final class SerializingReplicaPasswordStateStoreTest extends TestCase
{
    private const UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

    private ReplicaPasswordStateStoreInterface&MockObject $store;

    private RecordingWriterQueue $queue;

    private SerializingReplicaPasswordStateStore $subject;

    protected function setUp(): void
    {
        $this->store = $this->createMock(ReplicaPasswordStateStoreInterface::class);
        $this->queue = new RecordingWriterQueue();

        $this->subject = new SerializingReplicaPasswordStateStore(
            $this->store,
            $this->queue,
        );
    }

    public function test_load_reads_directly_without_the_queue(): void
    {
        $state = ReplicaPasswordState::empty();
        $this->store
            ->method('load')
            ->willReturn($state);

        self::assertSame(
            $state,
            $this->subject->load(self::UUID),
        );
        self::assertSame(
            0,
            $this->queue->runs,
        );
    }

    public function test_list_unforwarded_reads_directly_without_the_queue(): void
    {
        $this->store
            ->method('listUnforwarded')
            ->with(25)
            ->willReturn([]);

        self::assertSame(
            [],
            $this->subject->listUnforwarded(25),
        );
        self::assertSame(
            0,
            $this->queue->runs,
        );
    }

    public function test_atomic_mutate_runs_through_the_queue(): void
    {
        $merge = static fn(ReplicaPasswordState $state): OperationalChanges => OperationalChanges::none();
        $this->store
            ->expects(self::once())
            ->method('atomicMutate')
            ->with(
                self::UUID,
                $merge,
            );

        $this->subject->atomicMutate(
            self::UUID,
            $merge,
        );

        self::assertSame(
            1,
            $this->queue->runs,
        );
    }

    public function test_mark_forwarded_runs_through_the_queue(): void
    {
        $this->store
            ->expects(self::once())
            ->method('markForwarded')
            ->with(
                self::UUID,
                7,
            );

        $this->subject->markForwarded(
            self::UUID,
            7,
        );

        self::assertSame(
            1,
            $this->queue->runs,
        );
    }

    public function test_discard_if_superseded_runs_through_the_queue(): void
    {
        $authoritative = new UserPasswordState();
        $this->store
            ->expects(self::once())
            ->method('discardIfSuperseded')
            ->with(
                self::UUID,
                $authoritative,
            );

        $this->subject->discardIfSuperseded(
            self::UUID,
            $authoritative,
        );

        self::assertSame(
            1,
            $this->queue->runs,
        );
    }
}
