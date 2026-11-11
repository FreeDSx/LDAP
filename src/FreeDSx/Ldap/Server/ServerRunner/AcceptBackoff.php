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

namespace FreeDSx\Ldap\Server\ServerRunner;

use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Utility\ExponentialBackoff;
use FreeDSx\Socket\Exception\AcceptException;

/**
 * Spaces out accepts while they keep failing, such as when no descriptor is free, and logs each run of failures once.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class AcceptBackoff
{
    private int $failures = 0;

    public function __construct(
        private readonly ExponentialBackoff $delays = new ExponentialBackoff(
            base: 0.01,
            max: 1.0,
            jitter: 0.0,
        ),
    ) {}

    /**
     * Records a failed accept and returns the seconds to wait before accepting again.
     */
    public function failed(
        AcceptException $failure,
        EventLogger $events,
    ): float {
        if ($this->failures === 0) {
            $events->record(
                ServerEvent::ServerAcceptFailed,
                cause: $failure,
            );
        }
        $this->failures++;

        return $this->delays->delayFor($this->failures);
    }

    /**
     * Records an accept that succeeded, logging the recovery when failures came before it.
     */
    public function accepted(EventLogger $events): void
    {
        if ($this->failures === 0) {
            return;
        }

        $events->record(
            ServerEvent::ServerAcceptRecovered,
            ['failures' => $this->failures],
        );
        $this->failures = 0;
    }
}
