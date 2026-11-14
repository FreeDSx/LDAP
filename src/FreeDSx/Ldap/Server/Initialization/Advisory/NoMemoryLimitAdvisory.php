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

use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Initialization\AdvisoryInterface;
use FreeDSx\Ldap\Server\Initialization\InitializationWarning;
use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;
use FreeDSx\Ldap\Server\Resources\MemoryLimit;

/**
 * Without a memory limit, an unset held request size falls back to a fixed size the process may not have.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class NoMemoryLimitAdvisory implements AdvisoryInterface
{
    /**
     * @param int $heldRequestSize the bytes the requests of one process may hold at once, in effect.
     */
    public function __construct(
        private NetworkConfig $network,
        private MemoryLimit $memoryLimit,
        private int $heldRequestSize,
    ) {}

    public function warnings(): array
    {
        if ($this->network->getMaxHeldRequestSize() !== null || $this->memoryLimit->getBytes() !== null) {
            return [];
        }

        return [
            InitializationWarning::concurrencyLimited(
                ConcurrencyLimitReason::NoMemoryLimit,
                ['max_held_request_size' => $this->heldRequestSize],
            ),
        ];
    }
}
