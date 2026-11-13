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

namespace FreeDSx\Ldap\Protocol\Queue\Budget;

/**
 * Bytes counted against a request budget until the reservation is freed.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class BudgetReservation
{
    public function __construct(
        private readonly RequestBudget $budget,
        private readonly int $bytes,
    ) {}

    public function __destruct()
    {
        $this->budget->release($this->bytes);
    }
}
