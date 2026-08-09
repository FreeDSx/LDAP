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

namespace FreeDSx\Ldap\Server\Config\Replication;

use FreeDSx\Ldap\Exception\InvalidArgumentException;

/**
 * How a server serves RFC 4533 sync to downstream consumers.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ProviderConfig
{
    /**
     * Seconds between journal polls; also bounds change-delivery latency and dead-peer detection.
     */
    public const DEFAULT_POLL_INTERVAL = 1.0;

    private float $pollInterval = self::DEFAULT_POLL_INTERVAL;

    public function getPollInterval(): float
    {
        return $this->pollInterval;
    }

    /**
     * @throws InvalidArgumentException when the interval is not positive, which would poll without pause.
     */
    public function setPollInterval(float $pollInterval): self
    {
        if ($pollInterval <= 0) {
            throw new InvalidArgumentException('The sync poll interval must be greater than zero.');
        }

        $this->pollInterval = $pollInterval;

        return $this;
    }
}
