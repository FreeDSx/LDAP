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

use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Metrics\Observation\JournalObservation;
use FreeDSx\Ldap\Server\Metrics\Observation\OperationObservation;
use FreeDSx\Ldap\Server\Metrics\Observation\TrafficObservation;

/**
 * Sink that server components push metric observations to.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface MetricsRecorderInterface
{
    /**
     * Records a completed operation, also clearing the in-light counter.
     */
    public function operationObserved(OperationObservation $observation): void;

    /**
     * Marks an operation as entering the handler.
     */
    public function operationStarted(OperationType $operation): void;

    /**
     * Records a unit of transport traffic.
     */
    public function trafficObserved(TrafficObservation $observation): void;

    public function connectionObserved(ConnectionObservation $observation): void;

    /**
     * Records the outcome of a change-journal related operation.
     */
    public function journalObserved(JournalObservation $observation): void;

    /**
     * @param int $startedAt The server start time as a Unix timestamp.
     */
    public function serverStarted(int $startedAt): void;

    /**
     * @param int $reloadedAt The configuration reload time as a Unix timestamp.
     */
    public function serverReloaded(int $reloadedAt): void;
}
