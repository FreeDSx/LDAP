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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Queue\Budget\BudgetShare;
use FreeDSx\Ldap\Protocol\Queue\Budget\HeldResponse;
use FreeDSx\Ldap\Protocol\Queue\Budget\RequestBudget;
use FreeDSx\Ldap\Server\Resources\SystemResources;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Clock\CallbackSleeper;

final class HeldResponseTest extends TestCase
{
    private const LIMIT = 100_000;

    /**
     * What the entry built below holds: 34 bytes of DN and values, 3 values and 2 attributes.
     */
    private const ENTRY_HOLDS = 1_751;

    private RequestBudget $budget;

    private BudgetShare $share;

    private Entry $entry;

    private HeldResponse $subject;

    protected function setUp(): void
    {
        $this->budget = new RequestBudget(
            new CallbackSleeper(),
            $this->createMock(SystemResources::class),
        );
        $this->share = new BudgetShare(
            'dn:cn=user,dc=foo,dc=bar',
            self::ENTRY_HOLDS * 2,
        );
        $this->entry = Entry::create(
            'cn=user,dc=foo,dc=bar',
            [
                'cn' => 'user',
                'objectClass' => ['top', 'person'],
            ],
        );
        $this->subject = new HeldResponse(
            $this->budget,
            self::LIMIT,
            $this->share,
        );
    }

    public function test_it_estimates_an_entry_from_its_bytes_values_and_attributes(): void
    {
        self::assertSame(
            self::ENTRY_HOLDS,
            HeldResponse::estimate($this->entry),
        );
    }

    public function test_an_entry_with_room_is_counted_under_the_share(): void
    {
        self::assertSame(
            [true, self::ENTRY_HOLDS, self::ENTRY_HOLDS],
            [
                $this->subject->hold($this->entry),
                $this->budget->held(),
                $this->budget->heldBy($this->share),
            ],
        );
    }

    public function test_an_entry_past_the_share_is_not_counted(): void
    {
        $this->subject->hold($this->entry);
        $this->subject->hold($this->entry);

        self::assertSame(
            [false, self::ENTRY_HOLDS * 2],
            [
                $this->subject->hold($this->entry),
                $this->budget->held(),
            ],
        );
    }

    public function test_an_entry_past_what_the_process_may_hold_is_not_counted(): void
    {
        $otherConnections = $this->budget->reserveAnyway(
            self::LIMIT,
            new BudgetShare(
                'dn:cn=other,dc=foo,dc=bar',
                PHP_INT_MAX,
            ),
        );

        self::assertFalse($this->subject->hold($this->entry));
    }

    public function test_nothing_is_counted_without_a_limit(): void
    {
        $subject = new HeldResponse(
            $this->budget,
            0,
            $this->share,
        );

        self::assertSame(
            [true, 0],
            [
                $subject->hold($this->entry),
                $this->budget->held(),
            ],
        );
    }

    public function test_what_it_holds_is_released_once_it_is_freed(): void
    {
        $this->subject->hold($this->entry);

        unset($this->subject);

        self::assertSame(
            [0, 0],
            [$this->budget->held(), $this->budget->heldBy($this->share)],
        );
    }

    public function test_an_entry_larger_than_the_share_is_refused_as_past_the_admin_limit(): void
    {
        $subject = new HeldResponse(
            $this->budget,
            self::LIMIT,
            new BudgetShare(
                'dn:cn=user,dc=foo,dc=bar',
                self::ENTRY_HOLDS - 1,
            ),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $subject->refuse($this->entry);
    }

    public function test_an_entry_its_identity_has_no_room_for_is_refused_as_busy_for_the_identity(): void
    {
        $identityConnections = $this->budget->reserveAnyway(
            self::ENTRY_HOLDS * 2,
            $this->share,
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::BUSY);
        $this->expectExceptionMessage('The server holds as much as it allows one identity to.');

        $this->subject->refuse($this->entry);
    }

    public function test_an_entry_the_process_has_no_room_for_is_refused_as_busy(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::BUSY);
        $this->expectExceptionMessage('The server is too busy to hold the response.');

        $this->subject->refuse($this->entry);
    }
}
