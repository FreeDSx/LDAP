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
 * Starts what each response one connection collects before writing it holds, under the identity it is bound as.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class HeldResponses
{
    /**
     * @param int $limit the bytes the process may hold, or 0 for no limit.
     */
    public function __construct(
        private RequestBudget $budget,
        private int $limit,
        private IdentityShare $share,
    ) {}

    /**
     * What a response about to be collected holds, counted under the identity the connection is bound as now.
     */
    public function start(): HeldResponse
    {
        return new HeldResponse(
            $this->budget,
            $this->limit,
            $this->share->current(),
        );
    }
}
