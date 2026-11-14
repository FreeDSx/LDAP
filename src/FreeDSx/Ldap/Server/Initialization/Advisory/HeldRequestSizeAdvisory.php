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

namespace FreeDSx\Ldap\Server\Initialization\Advisory;

use FreeDSx\Ldap\Protocol\Queue\Budget\HeldRequests;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Initialization\AdvisoryInterface;
use FreeDSx\Ldap\Server\Initialization\InitializationWarning;
use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;

/**
 * A held request size smaller than what the largest request allowed holds refuses that request every time.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class HeldRequestSizeAdvisory implements AdvisoryInterface
{
    /**
     * @param int $heldRequestSize the bytes the requests of one process may hold at once, in effect, or 0 for no limit.
     */
    public function __construct(
        private NetworkConfig $network,
        private int $heldRequestSize,
    ) {}

    public function warnings(): array
    {
        $largestHeld = HeldRequests::largestHeld(
            $this->network->getMaxRequestSize(),
            $this->network->getMaxRequestElements(),
        );

        if ($this->heldRequestSize === 0 || $largestHeld <= $this->heldRequestSize) {
            return [];
        }

        return [
            InitializationWarning::concurrencyLimited(
                ConcurrencyLimitReason::HeldRequestSize,
                [
                    'max_held_request_size' => $this->heldRequestSize,
                    'max_request_size' => $this->network->getMaxRequestSize(),
                ],
            ),
        ];
    }
}
