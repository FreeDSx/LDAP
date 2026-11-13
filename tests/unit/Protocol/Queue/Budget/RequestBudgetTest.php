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

use FreeDSx\Ldap\Protocol\Queue\Budget\RequestBudget;
use FreeDSx\Ldap\Server\Resources\MemoryLimit;
use FreeDSx\Ldap\Server\Resources\SystemResources;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Clock\RecordingSleeper;

final class RequestBudgetTest extends TestCase
{
    private RecordingSleeper $sleeper;

    private SystemResources&MockObject $resources;

    private RequestBudget $subject;

    protected function setUp(): void
    {
        $this->sleeper = new RecordingSleeper();
        $this->resources = $this->createMock(SystemResources::class);
        $this->subject = new RequestBudget(
            $this->sleeper,
            $this->resources,
        );
    }

    public function test_the_limit_is_the_size_configured(): void
    {
        self::assertSame(
            1_000,
            $this->subject->limitFor(1_000),
        );
    }

    public function test_the_limit_is_half_of_the_memory_limit_when_no_size_is_configured(): void
    {
        $this->resources
            ->method('memoryLimit')
            ->willReturn(new MemoryLimit(134_217_728));

        self::assertSame(
            67_108_864,
            $this->subject->limitFor(null),
        );
    }

    public function test_the_limit_is_512_mib_without_a_memory_limit_or_a_size_configured(): void
    {
        $this->resources
            ->method('memoryLimit')
            ->willReturn(new MemoryLimit(null));

        self::assertSame(
            536_870_912,
            $this->subject->limitFor(null),
        );
    }

    public function test_it_reserves_bytes_that_fit_within_the_limit(): void
    {
        $reservation = $this->subject->reserve(
            600,
            1_000,
        );

        self::assertNotNull($reservation);
        self::assertSame(
            600,
            $this->subject->held(),
        );
    }

    public function test_it_refuses_bytes_past_the_limit(): void
    {
        $held = $this->subject->reserve(
            600,
            1_000,
        );

        self::assertNull($this->subject->reserve(
            500,
            1_000,
        ));
        self::assertSame(
            600,
            $this->subject->held(),
        );
    }

    public function test_it_reclaims_memory_once_before_refusing_bytes(): void
    {
        $this->resources
            ->expects(self::once())
            ->method('reclaimMemory');
        $held = $this->subject->reserveAnyway(1_000);

        $this->subject->reserve(
            1,
            1_000,
        );

        self::assertSame(
            1_000,
            $this->subject->held(),
        );
    }

    public function test_it_reserves_bytes_that_fit_once_memory_is_reclaimed(): void
    {
        $held = $this->subject->reserveAnyway(1_000);
        $this->resources
            ->method('reclaimMemory')
            ->willReturnCallback(static function () use (&$held): int {
                $held = null;

                return 1;
            });

        self::assertNotNull($this->subject->reserve(
            500,
            1_000,
        ));
    }

    public function test_it_does_not_reclaim_memory_for_bytes_that_could_never_fit(): void
    {
        $this->resources
            ->expects(self::never())
            ->method('reclaimMemory');

        self::assertNull($this->subject->reserve(
            1_001,
            1_000,
        ));
    }

    public function test_it_does_not_reclaim_memory_for_bytes_that_fit(): void
    {
        $this->resources
            ->expects(self::never())
            ->method('reclaimMemory');

        $this->subject->reserve(
            1_000,
            1_000,
        );
    }

    public function test_a_limit_of_zero_fits_any_size(): void
    {
        $held = $this->subject->reserveAnyway(1_000_000);

        $reservation = $this->subject->reserve(
            1_000_000,
            0,
        );

        self::assertNotNull($reservation);
        self::assertSame(
            2_000_000,
            $this->subject->held(),
        );
    }

    public function test_bytes_reserved_anyway_are_counted_past_the_limit(): void
    {
        $held = $this->subject->reserveAnyway(2_000);

        self::assertSame(
            2_000,
            $this->subject->held(),
        );
        self::assertFalse($this->subject->fits(
            1,
            1_000,
        ));
    }

    public function test_reserved_bytes_are_released_once_the_reservation_is_freed(): void
    {
        $reservation = $this->subject->reserve(
            600,
            1_000,
        );

        unset($reservation);

        self::assertSame(
            0,
            $this->subject->held(),
        );
    }

    public function test_it_does_not_wait_while_there_is_room(): void
    {
        $this->resources
            ->expects(self::never())
            ->method('reclaimMemory');

        self::assertTrue($this->subject->waitForRoom(
            static fn(): bool => true,
            null,
        ));
        self::assertSame(
            [],
            $this->sleeper->durations,
        );
    }

    public function test_it_waits_for_room_reclaiming_memory_first_and_then_polling(): void
    {
        $this->resources
            ->expects(self::once())
            ->method('reclaimMemory');
        $checks = 0;

        self::assertTrue($this->subject->waitForRoom(
            static function () use (&$checks): bool {
                return ++$checks > 3;
            },
            null,
        ));
        self::assertSame(
            [0.05, 0.05],
            $this->sleeper->durations,
        );
    }

    public function test_it_stops_waiting_for_room_once_the_deadline_passes(): void
    {
        $checks = 0;

        self::assertFalse($this->subject->waitForRoom(
            static function () use (&$checks): bool {
                return ++$checks > 100;
            },
            microtime(true) - 1,
        ));
    }
}
