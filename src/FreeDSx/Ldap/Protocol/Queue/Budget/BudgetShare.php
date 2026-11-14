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
 * The part of its process's request budget one identity may hold, counted under the identity's key.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class BudgetShare
{
    /**
     * @param int $limit the bytes the identity may hold.
     */
    public function __construct(
        public string $key,
        public int $limit,
    ) {}
}
