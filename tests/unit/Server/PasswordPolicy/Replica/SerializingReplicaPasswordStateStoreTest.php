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

use FreeDSx\Ldap\Entry\Dn;
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
    private const DN = 'cn=foo,dc=example,dc=com';

    private ReplicaPasswordStateStoreInterface&MockObject $reads;

    private ReplicaPasswordStateStoreInterface&MockObject $writes;

    private RecordingWriterQueue $queue;

    private SerializingReplicaPasswordStateStore $subject;

    protected function setUp(): void
    {
        $this->reads = $this->createMock(ReplicaPasswordStateStoreInterface::class);
        $this->writes = $this->createMock(ReplicaPasswordStateStoreInterface::class);
        $this->queue = new RecordingWriterQueue();

        $this->subject = new SerializingReplicaPasswordStateStore(
            $this->reads,
            $this->writes,
            $this->queue,
        );
    }

    public function test_load_reads_directly_without_the_queue(): void
    {
        $state = ReplicaPasswordState::empty();
        $this->reads
            ->method('load')
            ->willReturn($state);
        $this->writes->expects(self::never())->method('load');

        self::assertSame(
            $state,
            $this->subject->load(new Dn(self::DN)),
        );
        self::assertSame(
            0,
            $this->queue->runs,
        );
    }

    public function test_list_unforwarded_reads_directly_without_the_queue(): void
    {
        $this->reads
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

    public function test_atomic_mutate_runs_through_the_queue_against_the_writer(): void
    {
        $merge = static fn(ReplicaPasswordState $state): OperationalChanges => OperationalChanges::none();
        $this->writes
            ->expects(self::once())
            ->method('atomicMutate')
            ->with(
                new Dn(self::DN),
                $merge,
            );

        $this->subject->atomicMutate(
            new Dn(self::DN),
            $merge,
        );

        self::assertSame(
            1,
            $this->queue->runs,
        );
    }

    public function test_mark_forwarded_runs_through_the_queue_against_the_writer(): void
    {
        $this->writes
            ->expects(self::once())
            ->method('markForwarded')
            ->with(
                new Dn(self::DN),
                7,
            );

        $this->subject->markForwarded(
            new Dn(self::DN),
            7,
        );

        self::assertSame(
            1,
            $this->queue->runs,
        );
    }

    public function test_discard_if_superseded_runs_through_the_queue_against_the_writer(): void
    {
        $authoritative = new UserPasswordState();
        $this->writes
            ->expects(self::once())
            ->method('discardIfSuperseded')
            ->with(
                new Dn(self::DN),
                $authoritative,
            );

        $this->subject->discardIfSuperseded(
            new Dn(self::DN),
            $authoritative,
        );

        self::assertSame(
            1,
            $this->queue->runs,
        );
    }

    public function test_discard_runs_through_the_queue_against_the_writer(): void
    {
        $this->writes
            ->expects(self::once())
            ->method('discard')
            ->with(new Dn(self::DN));

        $this->subject->discard(new Dn(self::DN));

        self::assertSame(
            1,
            $this->queue->runs,
        );
    }
}
