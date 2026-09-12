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

namespace FreeDSx\Ldap\Server\Metrics;

/**
 * Records gauges that belong to one worker of a pool rather than to the pool as a whole.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface WorkerScopedMetricsInterface
{
    /**
     * Claims a worker's share of the gauges, discarding what an earlier incarnation of it left behind.
     */
    public function beginWorker(int $workerId): void;
}
