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

namespace Tests\Unit\FreeDSx\Ldap\Server\Process\Channel;

use FreeDSx\Ldap\Server\Process\Channel\ChildChannel;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Process\Channel\FakeChannelMessage;
use Tests\Support\FreeDSx\Ldap\Server\Process\Channel\FakeChannelMessageFactory;

final class ChildChannelTest extends TestCase
{
    private ChildChannel $subject;

    protected function setUp(): void
    {
        if (str_starts_with(strtoupper(PHP_OS), 'WIN')) {
            self::markTestSkipped('UNIX socket pairs are unavailable on Windows; the channel is Linux/PCNTL-only.');
        }

        $this->subject = ChildChannel::create(new FakeChannelMessageFactory());
    }

    public function test_a_sent_message_is_received_round_trip(): void
    {
        $this->subject->send(new FakeChannelMessage(['op' => 'search', 'n' => 2]));

        $received = $this->subject->receive();

        self::assertCount(
            1,
            $received,
        );
        self::assertSame(
            ['op' => 'search', 'n' => 2],
            $received[0]->toArray(),
        );
    }

    public function test_multiple_messages_are_received_in_order(): void
    {
        $this->subject->send(new FakeChannelMessage(['seq' => 1]));
        $this->subject->send(new FakeChannelMessage(['seq' => 2]));
        $this->subject->send(new FakeChannelMessage(['seq' => 3]));

        $received = $this->subject->receive();

        self::assertSame(
            [['seq' => 1], ['seq' => 2], ['seq' => 3]],
            array_map(
                static fn($message): array => $message->toArray(),
                $received,
            ),
        );
    }

    public function test_receiving_with_nothing_sent_returns_empty(): void
    {
        self::assertSame(
            [],
            $this->subject->receive(),
        );
    }

    public function test_the_read_buffer_persists_across_receive_calls(): void
    {
        $this->subject->send(new FakeChannelMessage(['seq' => 1]));
        self::assertCount(
            1,
            $this->subject->receive(),
        );

        $this->subject->send(new FakeChannelMessage(['seq' => 2]));
        $second = $this->subject->receive();

        self::assertSame(
            ['seq' => 2],
            $second[0]->toArray(),
        );
    }

    public function test_sending_to_a_full_channel_returns_rather_than_blocking(): void
    {
        $sends = 0;
        while ($this->subject->send(new FakeChannelMessage(['fill' => str_repeat('x', 1024)]))) {
            $sends++;
        }

        self::assertFalse($this->subject->flush());
        self::assertGreaterThan(
            0,
            $sends,
        );
    }

    public function test_a_frame_written_in_parts_arrives_whole_once_the_parent_reads(): void
    {
        $payload = str_repeat('y', 256 * 1024);
        $received = [];

        $this->subject->send(new FakeChannelMessage(['big' => $payload]));
        while ($received === []) {
            $received = $this->subject->receive();
            $this->subject->flush();
        }

        self::assertSame(
            ['big' => $payload],
            $received[0]->toArray(),
        );
    }

    public function test_draining_a_channel_nobody_reads_gives_up_at_its_timeout(): void
    {
        while ($this->subject->send(new FakeChannelMessage(['fill' => str_repeat('x', 1024)]))) {
        }
        $startedAt = microtime(true);

        $drained = $this->subject->drain(0.2);

        self::assertFalse($drained);
        self::assertLessThan(
            1.0,
            microtime(true) - $startedAt,
        );
    }

    public function test_remaining_messages_are_drained_after_the_write_end_closes(): void
    {
        $this->subject->send(new FakeChannelMessage(['final' => true]));
        $this->subject->closeWrite();

        $received = $this->subject->receive();

        self::assertSame(
            ['final' => true],
            $received[0]->toArray(),
        );
        self::assertSame(
            [],
            $this->subject->receive(),
        );
    }
}
