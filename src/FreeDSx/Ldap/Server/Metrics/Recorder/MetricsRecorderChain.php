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

namespace FreeDSx\Ldap\Server\Metrics\Recorder;

use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Metrics\Observation\JournalObservation;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Observation\OperationObservation;
use FreeDSx\Ldap\Server\Metrics\Observation\TrafficObservation;
use FreeDSx\Ldap\Server\Metrics\WorkerScopedMetricsInterface;

use function array_values;

/**
 * Fans every observation out to several recorders, e.g. an in-memory recorder for cn=monitor and a push exporter.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class MetricsRecorderChain implements MetricsRecorderInterface, WorkerScopedMetricsInterface
{
    /**
     * @var list<MetricsRecorderInterface>
     */
    private array $recorders;

    public function __construct(MetricsRecorderInterface ...$recorders)
    {
        $this->recorders = array_values($recorders);
    }

    public function beginWorker(int $workerId): void
    {
        foreach ($this->recorders as $recorder) {
            if (!$recorder instanceof WorkerScopedMetricsInterface) {
                continue;
            }

            $recorder->beginWorker($workerId);
        }
    }

    public function operationObserved(OperationObservation $observation): void
    {
        foreach ($this->recorders as $recorder) {
            $recorder->operationObserved($observation);
        }
    }

    public function operationStarted(OperationType $operation): void
    {
        foreach ($this->recorders as $recorder) {
            $recorder->operationStarted($operation);
        }
    }

    public function trafficObserved(TrafficObservation $observation): void
    {
        foreach ($this->recorders as $recorder) {
            $recorder->trafficObserved($observation);
        }
    }

    public function connectionObserved(ConnectionObservation $observation): void
    {
        foreach ($this->recorders as $recorder) {
            $recorder->connectionObserved($observation);
        }
    }

    public function journalObserved(JournalObservation $observation): void
    {
        foreach ($this->recorders as $recorder) {
            $recorder->journalObserved($observation);
        }
    }

    public function serverStarted(int $startedAt): void
    {
        foreach ($this->recorders as $recorder) {
            $recorder->serverStarted($startedAt);
        }
    }

    public function serverReloaded(int $reloadedAt): void
    {
        foreach ($this->recorders as $recorder) {
            $recorder->serverReloaded($reloadedAt);
        }
    }
}
