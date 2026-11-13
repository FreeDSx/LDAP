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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Queue;

use FreeDSx\Asn1\Encoder\EncoderOptions;
use FreeDSx\Ldap\Exception\RequestRefusedException;
use FreeDSx\Ldap\Exception\RequestSizeExceededException;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Budget\HeldRequests;
use FreeDSx\Ldap\Protocol\Queue\Budget\RequestBudget;
use FreeDSx\Ldap\Protocol\Queue\RequestArrival;
use FreeDSx\Ldap\Protocol\Queue\RequestLimits;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\Resources\SystemResources;
use FreeDSx\Socket\Exception\ConnectionException;
use FreeDSx\Socket\Exception\IdleTimeoutException;
use FreeDSx\Socket\Exception\PartialMessageException;
use FreeDSx\Socket\Exception\ReadTimeoutException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Clock\CallbackSleeper;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class RequestArrivalTest extends TestCase
{
    private ServerAuthorization $authorization;

    private SystemResources&MockObject $resources;

    private RequestBudget $budget;

    protected function setUp(): void
    {
        $this->authorization = new ServerAuthorization(TestServerOptions::defaults());
        $this->resources = $this->createMock(SystemResources::class);
        $this->budget = new RequestBudget(
            new CallbackSleeper(
                static fn(): null => usleep(100_000),
            ),
            $this->resources,
        );
    }

    public function test_it_holds_the_encoder_to_the_size_the_session_may_send(): void
    {
        $encoder = new LdapEncoder();

        $this->arrivalWith(maxSize: 1_000)->limitDecoding($encoder);

        self::assertEquals(
            new EncoderOptions(
                maxLength: 1_000,
                maxElements: 50,
                maxTagNumber: 30,
            ),
            $encoder->getOptions(),
        );
    }

    public function test_it_leaves_the_encoder_alone_while_the_size_the_session_may_send_is_unchanged(): void
    {
        $encoder = $this->createMock(LdapEncoder::class);
        $encoder->expects(self::once())
            ->method('setOptions');
        $subject = $this->arrivalWith(maxSize: 1_000);

        $subject->limitDecoding($encoder);
        $subject->limitDecoding($encoder);
    }

    public function test_it_leaves_a_read_between_requests_to_the_idle_timeout(): void
    {
        self::assertNull($this->arrivalWith(readTimeout: 30)->readTimeout(false));
    }

    public function test_it_leaves_a_read_to_the_idle_timeout_without_a_read_timeout(): void
    {
        self::assertNull($this->arrivalWith(readTimeout: 0)->readTimeout(true));
    }

    public function test_a_request_that_has_begun_to_arrive_has_the_read_timeout_left_to_finish(): void
    {
        $subject = $this->arrivalWith(readTimeout: 30);

        $first = $subject->readTimeout(true);
        $second = $subject->readTimeout(true);

        self::assertGreaterThan(
            29.9,
            $first,
        );
        self::assertLessThanOrEqual(
            30.0,
            $first,
        );
        self::assertLessThanOrEqual(
            $first,
            $second,
        );
    }

    public function test_each_request_has_the_whole_read_timeout_to_arrive(): void
    {
        $subject = $this->arrivalWith(readTimeout: 30);
        $subject->readTimeout(true);
        usleep(50_000);

        $subject->arrived();

        self::assertGreaterThan(
            29.99,
            $subject->readTimeout(true),
        );
    }

    public function test_a_read_that_timed_out_is_reported_as_the_request_taking_too_long(): void
    {
        $timeout = new ReadTimeoutException('The read did not complete within its timeout of 30 seconds.');

        self::expectException(ReadTimeoutException::class);
        self::expectExceptionMessage('The request did not finish arriving within 30 seconds.');

        $this->arrivalWith(readTimeout: 30)->timedOut($timeout);
    }

    public function test_nothing_is_admitted_before_a_request_declares_its_length(): void
    {
        $subject = $this->arrivalWith(heldSize: 100_000);

        $subject->arriving(null);
        $subject->admit();

        self::assertSame(
            0,
            $this->budget->held(),
        );
    }

    public function test_a_request_is_admitted_at_what_its_declared_bytes_will_hold(): void
    {
        $subject = $this->arrivalWith(heldSize: 100_000);
        $subject->arriving(50_000);

        $subject->admit();

        self::assertSame(
            57_820,
            $this->budget->held(),
        );
    }

    public function test_a_request_is_admitted_at_once_when_the_process_has_room(): void
    {
        $subject = $this->arrivalWith(heldSize: 100_000);
        $subject->arriving(50_000);

        $subject->admitAtOnce();

        self::assertSame(
            57_820,
            $this->budget->held(),
        );
    }

    public function test_a_request_without_room_is_not_admitted_at_once_and_its_time_to_arrive_starts_over(): void
    {
        $subject = $this->arrivalWith(
            readTimeout: 30,
            heldSize: 100_000,
        );
        $otherConnections = $this->budget->reserveAnyway(100_000);
        $subject->readTimeout(true);
        $subject->arriving(50_000);
        $this->resources
            ->expects(self::never())
            ->method('reclaimMemory');

        try {
            $subject->admitAtOnce();
            self::fail('The request should not have been admitted.');
        } catch (PartialMessageException) {
            usleep(50_000);

            self::assertSame(
                100_000,
                $this->budget->held(),
            );
            self::assertGreaterThan(
                29.99,
                $subject->readTimeout(true),
            );
        }
    }

    public function test_it_waits_to_admit_a_request_until_memory_is_reclaimed(): void
    {
        $subject = $this->arrivalWith(heldSize: 100_000);
        $otherConnections = $this->budget->reserveAnyway(100_000);
        $subject->arriving(50_000);
        $this->resources
            ->expects(self::once())
            ->method('reclaimMemory')
            ->willReturnCallback(static function () use (&$otherConnections): int {
                $otherConnections = null;

                return 1;
            });

        $subject->admit();

        self::assertSame(
            57_820,
            $this->budget->held(),
        );
    }

    public function test_a_request_that_runs_out_of_time_waiting_to_be_admitted_is_reported_as_finding_no_room(): void
    {
        $subject = $this->arrivalWith(
            readTimeout: 1,
            heldSize: 100_000,
        );
        $otherConnections = $this->budget->reserveAnyway(100_000);
        $subject->arriving(50_000);

        self::expectException(ReadTimeoutException::class);
        self::expectExceptionMessage('The server had no room to read the rest of the request within 1 seconds.');

        $subject->admit();
    }

    public function test_without_a_read_timeout_the_wait_to_be_admitted_ends_at_the_idle_timeout(): void
    {
        $subject = $this->arrivalWith(
            heldSize: 100_000,
            idleTimeout: 1,
        );
        $otherConnections = $this->budget->reserveAnyway(100_000);
        $subject->arriving(50_000);

        self::expectException(IdleTimeoutException::class);
        self::expectExceptionMessage(
            'The connection waited for room to read for longer than the idle timeout of 1 seconds.',
        );

        $subject->admit();
    }

    public function test_a_request_whose_declared_bytes_will_hold_more_than_the_process_ever_could_is_too_large(): void
    {
        self::expectException(RequestSizeExceededException::class);
        self::expectExceptionMessage('The request is larger than the server can hold.');

        $this->arrivalWith(heldSize: 100_000)->arriving(90_000);
    }

    public function test_what_a_request_reserved_while_arriving_is_released_once_it_arrived(): void
    {
        $subject = $this->arrivalWith(heldSize: 100_000);
        $subject->arriving(50_000);
        $subject->admit();

        $subject->arrived();

        self::assertSame(
            0,
            $this->budget->held(),
        );
    }

    public function test_a_request_that_arrived_leaves_no_declared_length_for_the_next_read_to_admit(): void
    {
        $subject = $this->arrivalWith(heldSize: 100_000);
        $subject->arriving(50_000);
        $subject->admit();
        $subject->arrived();

        $subject->admit();

        self::assertSame(
            0,
            $this->budget->held(),
        );
    }

    public function test_closing_the_connection_ends_a_wait_to_admit_a_request(): void
    {
        $subject = $this->arrivalWith(
            readTimeout: 30,
            heldSize: 100_000,
        );
        $otherConnections = $this->budget->reserveAnyway(100_000);
        $subject->arriving(50_000);
        $this->resources
            ->method('reclaimMemory')
            ->willReturnCallback(static function () use ($subject): int {
                $subject->close();

                return 1;
            });

        self::expectException(ConnectionException::class);

        $subject->admit();
    }

    public function test_it_counts_a_decoded_request_against_the_process_budget(): void
    {
        $subject = $this->arrivalWith(heldSize: 100_000);
        $request = new LdapMessageRequest(
            7,
            Operations::delete('cn=foo,dc=foo,dc=bar'),
        );

        $isHeld = $subject->hold(
            $request,
            1_000,
            10,
        );

        self::assertSame(
            [
                true,
                HeldRequests::estimate(
                    1_000,
                    10,
                ),
            ],
            [$isHeld, $this->budget->held()],
        );
    }

    public function test_a_decoded_request_the_process_has_no_room_to_hold_is_not_held(): void
    {
        $subject = $this->arrivalWith(heldSize: 100_000);
        $otherConnections = $this->budget->reserveAnyway(100_000);

        self::assertFalse($subject->hold(
            new LdapMessageRequest(
                7,
                Operations::delete('cn=foo,dc=foo,dc=bar'),
            ),
            10_000,
            0,
        ));
    }

    public function test_a_request_there_was_no_room_to_hold_is_refused(): void
    {
        self::expectException(RequestRefusedException::class);

        $this->arrivalWith(heldSize: 100_000)->refuse(
            7,
            10,
            10_000,
            0,
        );
    }

    public function test_requests_are_not_read_ahead_once_the_process_holds_all_it_may(): void
    {
        $subject = $this->arrivalWith(heldSize: 100_000);
        $otherConnections = $this->budget->reserveAnyway(100_000);

        self::assertFalse($subject->hasRoomToReadAhead());
    }

    private function arrivalWith(
        int $maxSize = 0,
        int $readTimeout = 0,
        int $heldSize = 0,
        int $idleTimeout = -1,
    ): RequestArrival {
        return new RequestArrival(
            new RequestLimits(
                $this->authorization,
                maxSize: $maxSize,
                maxElements: 50,
                readTimeout: $readTimeout,
                idleTimeout: $idleTimeout,
            ),
            new HeldRequests(
                $this->budget,
                $heldSize,
            ),
        );
    }
}
