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

use FreeDSx\Ldap\Protocol\Queue\Budget\BudgetReservation;
use FreeDSx\Ldap\Protocol\Queue\Budget\RequestBudget;
use FreeDSx\Ldap\Server\Resources\SystemResources;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Clock\RecordingSleeper;

final class BudgetReservationTest extends TestCase
{
    private RequestBudget $budget;

    private BudgetReservation $subject;

    protected function setUp(): void
    {
        $this->budget = new RequestBudget(
            new RecordingSleeper(),
            $this->createMock(SystemResources::class),
        );
        $this->subject = new BudgetReservation(
            $this->budget,
            300,
        );
    }

    public function test_it_releases_its_bytes_once_freed(): void
    {
        $held = $this->budget->held();

        unset($this->subject);

        self::assertSame(
            $held - 300,
            $this->budget->held(),
        );
    }
}
