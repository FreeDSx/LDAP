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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Queue\Budget;

use FreeDSx\Ldap\Exception\RequestRefusedException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Budget\BudgetReservation;
use FreeDSx\Ldap\Protocol\Queue\Budget\HeldRequests;
use FreeDSx\Ldap\Protocol\Queue\Budget\RequestBudget;
use FreeDSx\Ldap\Server\Resources\SystemResources;
use FreeDSx\Socket\Exception\ConnectionException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Clock\CallbackSleeper;

final class HeldRequestsTest extends TestCase
{
    private const LIMIT = 100_000;

    private SystemResources&MockObject $resources;

    private RequestBudget $budget;

    private HeldRequests $subject;

    protected function setUp(): void
    {
        $this->resources = $this->createMock(SystemResources::class);
        $this->budget = new RequestBudget(
            new CallbackSleeper(),
            $this->resources,
        );
        $this->subject = new HeldRequests(
            $this->budget,
            self::LIMIT,
        );
    }

    public function test_it_estimates_what_a_decoded_request_holds_from_its_bytes_and_elements(): void
    {
        self::assertSame(
            2_750,
            HeldRequests::estimate(
                1_000,
                10,
            ),
        );
    }

    public function test_a_request_that_fits_is_admitted_at_what_its_declared_bytes_will_hold(): void
    {
        self::assertSame(
            [true, 57_820],
            [
                $this->subject->admit(
                    50_000,
                    null,
                ),
                $this->budget->held(),
            ],
        );
    }

    public function test_a_request_admitted_again_is_counted_once(): void
    {
        $this->subject->admit(
            50_000,
            null,
        );
        $this->subject->admit(
            50_000,
            null,
        );

        self::assertSame(
            57_820,
            $this->budget->held(),
        );
    }

    public function test_a_request_estimated_at_the_floor_is_admitted_even_when_the_process_has_no_room(): void
    {
        $otherConnections = $this->fillTheBudget();

        self::assertSame(
            [true, self::LIMIT + 4_096],
            [
                $this->subject->admit(
                    3_283,
                    microtime(true) - 1,
                ),
                $this->budget->held(),
            ],
        );
    }

    public function test_a_request_estimated_past_the_floor_is_not_admitted_when_the_process_has_no_room(): void
    {
        $otherConnections = $this->fillTheBudget();

        self::assertSame(
            [false, self::LIMIT],
            [
                $this->subject->tryAdmit(3_284),
                $this->budget->held(),
            ],
        );
    }

    public function test_a_request_is_admitted_at_once_when_the_process_has_room(): void
    {
        self::assertSame(
            [true, 57_820],
            [
                $this->subject->tryAdmit(50_000),
                $this->budget->held(),
            ],
        );
    }

    public function test_a_request_is_not_admitted_at_once_without_room_and_nothing_is_reclaimed(): void
    {
        $otherConnections = $this->fillTheBudget();
        $this->resources
            ->expects(self::never())
            ->method('reclaimMemory');

        self::assertSame(
            [false, self::LIMIT],
            [
                $this->subject->tryAdmit(50_000),
                $this->budget->held(),
            ],
        );
    }

    public function test_a_request_is_admitted_without_being_counted_when_there_is_no_limit(): void
    {
        $subject = new HeldRequests(
            $this->budget,
            0,
        );
        $otherConnections = $this->fillTheBudget();

        self::assertSame(
            [true, self::LIMIT],
            [
                $subject->admit(
                    50_000,
                    microtime(true) - 1,
                ),
                $this->budget->held(),
            ],
        );
    }

    public function test_what_a_request_reserved_while_arriving_is_released_once_it_arrived(): void
    {
        $this->subject->admit(
            50_000,
            null,
        );

        $this->subject->arrived();

        self::assertSame(
            0,
            $this->budget->held(),
        );
    }

    public function test_a_closed_connection_admits_nothing(): void
    {
        $this->subject->close();

        $this->expectException(ConnectionException::class);

        $this->subject->tryAdmit(50_000);
    }

    public function test_closing_the_connection_ends_its_wait_for_room_without_reserving(): void
    {
        $otherConnections = $this->fillTheBudget();
        $this->resources
            ->method('reclaimMemory')
            ->willReturnCallback(function () use (&$otherConnections): int {
                $this->subject->close();
                $otherConnections = null;

                return 1;
            });

        try {
            $this->subject->admit(
                50_000,
                null,
            );
            self::fail('The wait should have ended with the connection.');
        } catch (ConnectionException) {
            self::assertSame(
                0,
                $this->budget->held(),
            );
        }
    }

    public function test_what_a_request_reserved_while_arriving_is_released_once_the_connection_is_freed(): void
    {
        $this->subject->admit(
            50_000,
            null,
        );

        unset($this->subject);

        self::assertSame(
            0,
            $this->budget->held(),
        );
    }

    public function test_a_request_whose_declared_bytes_will_hold_more_than_the_limit_could_never_be_admitted(): void
    {
        self::assertSame(
            [true, false],
            [
                $this->subject->couldEverAdmit(86_678),
                $this->subject->couldEverAdmit(86_679),
            ],
        );
    }

    public function test_only_a_request_estimated_within_the_floor_could_be_admitted_under_a_smaller_limit(): void
    {
        $subject = new HeldRequests(
            $this->budget,
            1_000,
        );

        self::assertSame(
            [true, false],
            [
                $subject->couldEverAdmit(3_283),
                $subject->couldEverAdmit(3_284),
            ],
        );
    }

    public function test_it_counts_a_decoded_request_for_as_long_as_it_is_alive(): void
    {
        $request = self::request(7);
        $isHeld = $this->subject->hold(
            $request,
            10_000,
            10,
        );
        $held = $this->budget->held();

        unset($request);

        self::assertSame(
            [true, 13_100, 0],
            [$isHeld, $held, $this->budget->held()],
        );
    }

    public function test_a_request_the_process_has_no_room_to_hold_is_neither_held_nor_counted(): void
    {
        $otherConnections = $this->fillTheBudget(95_000);

        self::assertSame(
            [false, 95_000],
            [
                $this->subject->hold(
                    self::request(7),
                    10_000,
                    0,
                ),
                $this->budget->held(),
            ],
        );
    }

    public function test_a_request_there_was_no_room_for_is_refused_as_busy_on_its_message_id(): void
    {
        try {
            $this->subject->refuse(
                7,
                10,
                10_000,
                0,
            );
        } catch (RequestRefusedException $e) {
            self::assertSame(
                [7, 10, ResultCode::BUSY],
                [$e->getMessageId(), $e->getProtocolOpTag(), $e->getResultCode()],
            );
        }
    }

    public function test_a_request_larger_than_the_limit_is_refused_as_past_the_admin_limit(): void
    {
        try {
            $this->subject->refuse(
                7,
                10,
                self::LIMIT,
                0,
            );
        } catch (RequestRefusedException $e) {
            self::assertSame(
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                $e->getResultCode(),
            );
        }
    }

    public function test_a_request_estimated_at_exactly_the_limit_is_refused_as_busy(): void
    {
        try {
            $this->subject->refuse(
                7,
                10,
                0,
                625,
            );
        } catch (RequestRefusedException $e) {
            self::assertSame(
                ResultCode::BUSY,
                $e->getResultCode(),
            );
        }
    }

    public function test_a_request_estimated_at_the_floor_is_held_even_when_the_process_has_no_room(): void
    {
        $otherConnections = $this->fillTheBudget();
        $request = self::request(7);

        $isHeld = $this->subject->hold(
            $request,
            779,
            20,
        );

        self::assertSame(
            [true, self::LIMIT + 4_096],
            [$isHeld, $this->budget->held()],
        );
    }

    public function test_a_small_request_holding_many_elements_is_not_held_when_the_process_has_no_room(): void
    {
        $otherConnections = $this->fillTheBudget();

        self::assertFalse($this->subject->hold(
            self::request(7),
            2_000,
            500,
        ));
    }

    /**
     * @return iterable<string, array{RequestInterface}>
     */
    public static function noResponseProvider(): iterable
    {
        yield 'abandon' => [new AbandonRequest(1)];
        yield 'unbind' => [new UnbindRequest()];
    }

    #[DataProvider('noResponseProvider')]
    public function test_an_operation_with_no_response_past_the_floor_is_not_held_when_the_process_has_no_room(
        RequestInterface $operation,
    ): void {
        $otherConnections = $this->fillTheBudget();

        self::assertFalse($this->subject->hold(
            new LdapMessageRequest(
                7,
                $operation,
            ),
            10_000,
            0,
        ));
    }

    public function test_nothing_is_counted_for_a_request_without_a_limit(): void
    {
        $subject = new HeldRequests(
            $this->budget,
            0,
        );
        $request = self::request(7);

        $isHeld = $subject->hold(
            $request,
            10_000,
            0,
        );

        self::assertSame(
            [true, 0],
            [$isHeld, $this->budget->held()],
        );
    }

    public function test_requests_may_be_read_ahead_while_the_process_holds_less_than_it_may(): void
    {
        $otherConnections = $this->fillTheBudget(self::LIMIT - 1);

        self::assertTrue($this->subject->hasRoomToReadAhead());
    }

    public function test_requests_are_not_read_ahead_once_the_process_holds_all_it_may(): void
    {
        $otherConnections = $this->fillTheBudget();

        self::assertFalse($this->subject->hasRoomToReadAhead());
    }

    public function test_requests_may_always_be_read_ahead_without_a_limit(): void
    {
        $subject = new HeldRequests(
            $this->budget,
            0,
        );
        $otherConnections = $this->fillTheBudget();

        self::assertTrue($subject->hasRoomToReadAhead());
    }

    public function test_it_waits_to_admit_a_request_until_reclaimed_memory_makes_room(): void
    {
        $otherConnections = $this->fillTheBudget();
        $this->resources
            ->expects(self::once())
            ->method('reclaimMemory')
            ->willReturnCallback(static function () use (&$otherConnections): int {
                $otherConnections = null;

                return 1;
            });

        self::assertSame(
            [true, 57_820],
            [
                $this->subject->admit(
                    50_000,
                    null,
                ),
                $this->budget->held(),
            ],
        );
    }

    public function test_it_gives_up_admitting_a_request_once_the_deadline_passes(): void
    {
        $otherConnections = $this->fillTheBudget();

        self::assertSame(
            [false, self::LIMIT],
            [
                $this->subject->admit(
                    50_000,
                    microtime(true) - 1,
                ),
                $this->budget->held(),
            ],
        );
    }

    /**
     * What the process's other connections hold, counted for as long as the reservation is kept.
     */
    private function fillTheBudget(int $bytes = self::LIMIT): BudgetReservation
    {
        return $this->budget->reserveAnyway($bytes);
    }

    private static function request(int $messageId): LdapMessageRequest
    {
        return new LdapMessageRequest(
            $messageId,
            Operations::delete('cn=foo,dc=foo,dc=bar'),
        );
    }
}
