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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Queue\Response;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\DecodeFailureResponder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\Cancellation;
use FreeDSx\Ldap\Protocol\Queue\Response\OutOfSequenceResponder;
use FreeDSx\Ldap\Protocol\Queue\Response\QueueWriterConfig;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseWriter;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use Generator;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ResponseWriterTest extends TestCase
{
    private ServerQueue&MockObject $queue;

    private Cancellation $cancellation;

    private LdapMessageRequest $cancel;

    private ResponseWriter $subject;

    protected function setUp(): void
    {
        $this->queue = $this->createMock(ServerQueue::class);
        $this->cancellation = new Cancellation();
        $this->cancel = new LdapMessageRequest(
            3,
            new CancelRequest(2),
        );

        $this->subject = new ResponseWriter(
            $this->queue,
            new DecodeFailureResponder($this->queue),
            new OutOfSequenceResponder($this->queue),
        );
    }

    public function test_a_persistent_stream_polls_for_waiting_requests_rather_than_peeking(): void
    {
        $this->queue
            ->expects(self::never())
            ->method('peekForCancelSignal');
        $this->queue
            ->expects(self::atLeastOnce())
            ->method('pollMessage')
            ->willReturn(null);

        $this->subject->write(
            $this->stream(
                count: 2,
                observes: false,
                persistent: true,
            ),
            2,
        );
    }

    public function test_a_finite_stream_peeks_rather_than_polling_for_waiting_requests(): void
    {
        $this->queue
            ->expects(self::never())
            ->method('pollMessage');
        $this->queue
            ->expects(self::atLeastOnce())
            ->method('peekForCancelSignal')
            ->willReturn(null);

        $this->subject->write(
            $this->stream(
                count: 2,
                observes: false,
            ),
            2,
        );
    }

    public function test_a_persistent_stream_stops_polling_once_the_producer_has_a_signal(): void
    {
        $this->queue
            ->expects(self::once())
            ->method('pollMessage')
            ->willReturn($this->cancel);

        $this->subject->write(
            $this->stream(
                count: 3,
                observes: false,
                persistent: true,
            ),
            2,
        );
    }

    public function test_it_stops_polling_once_the_producer_has_a_signal(): void
    {
        $this->queue
            ->expects(self::once())
            ->method('peekForCancelSignal')
            ->willReturn($this->cancel);

        $this->subject->write(
            $this->stream(
                count: 3,
                observes: false,
            ),
            2,
        );
    }

    public function test_a_cancel_the_stream_ended_without_looking_at_is_left_for_the_dispatcher(): void
    {
        $this->queue
            ->method('peekForCancelSignal')
            ->willReturn($this->cancel);
        $this->queue
            ->expects(self::once())
            ->method('buffer')
            ->with($this->cancel);

        $this->subject->write(
            $this->stream(
                count: 1,
                observes: false,
            ),
            2,
        );
    }

    public function test_a_cancel_the_producer_looked_at_is_not_left_for_the_dispatcher(): void
    {
        $this->queue
            ->method('peekForCancelSignal')
            ->willReturn($this->cancel);
        $this->queue
            ->expects(self::never())
            ->method('buffer');

        $this->subject->write(
            $this->stream(
                count: 3,
                observes: true,
            ),
            2,
        );
    }

    public function test_a_cancel_is_left_for_the_dispatcher_when_the_stream_fails_before_looking_at_it(): void
    {
        $this->queue
            ->method('peekForCancelSignal')
            ->willReturn($this->cancel);
        $this->queue
            ->expects(self::once())
            ->method('buffer')
            ->with($this->cancel);

        $this->expectException(RuntimeException::class);

        $this->subject->write(
            ResponseStream::streaming(
                $this->failingAfterOneMessage(),
                static fn(): OperationOutcomeResult => OperationOutcomeResult::succeeded(),
                new QueueWriterConfig(signalInterval: 1),
                $this->cancellation,
            ),
            2,
        );
    }

    private function stream(
        int $count,
        bool $observes,
        bool $persistent = false,
    ): ResponseStream {
        return ResponseStream::streaming(
            $this->messages(
                $count,
                $observes,
            ),
            static fn(): OperationOutcomeResult => OperationOutcomeResult::succeeded(),
            new QueueWriterConfig(
                signalInterval: 1,
                persistent: $persistent,
            ),
            $this->cancellation,
        );
    }

    /**
     * @return Generator<LdapMessageResponse>
     */
    private function messages(
        int $count,
        bool $observes,
    ): Generator {
        for ($i = 1; $i <= $count; $i++) {
            yield new LdapMessageResponse(
                2,
                new SearchResultEntry(Entry::create("cn=$i,dc=foo,dc=bar")),
            );

            if ($observes && $this->cancellation->isSignalled()) {
                return;
            }
        }
    }

    /**
     * @return Generator<LdapMessageResponse>
     */
    private function failingAfterOneMessage(): Generator
    {
        yield new LdapMessageResponse(
            2,
            new SearchResultEntry(Entry::create('cn=1,dc=foo,dc=bar')),
        );

        throw new RuntimeException('The storage could not be read.');
    }
}
