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

namespace FreeDSx\Ldap\Server\ServerRunner\Pcntl;

use FreeDSx\Ldap\Exception\MetricsSnapshotException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Logging\ExceptionLogging;
use FreeDSx\Ldap\Server\Metrics\File\SnapshotPublisher;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationRollupCoordinator;
use FreeDSx\Ldap\Server\Process\Child\ChildProcess;
use FreeDSx\Ldap\Server\Process\Child\ReapedChild;
use Psr\Log\LoggerInterface;

use function getmypid;
use function time;

/**
 * Gathers a forking server's metrics in the parent, from its own events and its children's, and publishes them for
 * cn=monitor.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class MetricsRelay
{
    private bool $isSnapshotFailing = false;

    /**
     * @param ?SnapshotPublisher $snapshotPublisher Null when cn=monitor is off.
     * @param ?OperationRollupCoordinator $operationRollup Null when cn=monitor is off.
     */
    public function __construct(
        private readonly MetricsRecorderInterface $recorder = new NullMetricsRecorder(),
        private readonly ?SnapshotPublisher $snapshotPublisher = null,
        private readonly ?OperationRollupCoordinator $operationRollup = null,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    /**
     * @throws MetricsSnapshotException when the snapshot location cannot be readied.
     */
    public function prepare(): void
    {
        $this->snapshotPublisher?->prepare();
    }

    public function remove(): void
    {
        $this->snapshotPublisher?->remove();
    }

    public function serverStarted(): void
    {
        $this->recorder->serverStarted(time());
        $this->publish();
    }

    public function serverReloaded(): void
    {
        $this->recorder->serverReloaded(time());
        $this->publish();
    }

    public function connectionRejected(): void
    {
        $this->recorder->connectionObserved(ConnectionObservation::Rejected);
        $this->publish();
    }

    /**
     * Null when nothing collects a child's operations, or its channel cannot be made.
     */
    public function openChildReporter(): ?ChildReporter
    {
        if ($this->operationRollup === null) {
            return null;
        }

        try {
            return new ChildReporter(
                $this->operationRollup->openChannel(),
                $this->operationRollup,
            );
        } catch (RuntimeException $e) {
            $this->logger?->info(
                'Unable to create a child metrics channel; continuing without operation rollup.',
                ['pid' => getmypid()] + ExceptionLogging::makeLogContext($e),
            );

            return null;
        }
    }

    public function childStarted(): void
    {
        $this->recorder->connectionObserved(ConnectionObservation::Opened);
    }

    /**
     * Takes each reaped child's last operations and close reason, folds in what the running ones reported, and publishes.
     *
     * @param list<ReapedChild> $reaped
     * @param list<ChildProcess> $running
     */
    public function sweep(
        array $reaped,
        array $running,
    ): void {
        foreach ($reaped as $child) {
            $this->collect($child->process);
            $child->process->getChannel()?->close();
            $this->recordClose($child);
        }

        foreach ($running as $child) {
            $this->collect($child);
        }

        $this->publish();
    }

    private function collect(ChildProcess $child): void
    {
        $channel = $child->getChannel();

        if ($channel === null || $this->operationRollup === null) {
            return;
        }

        $this->operationRollup->collect($channel);
    }

    private function recordClose(ReapedChild $child): void
    {
        $this->recorder->connectionObserved(ConnectionObservation::Closed);

        if ($child->closeReason !== null) {
            $this->recorder->connectionObserved($child->closeReason);
        }
    }

    /**
     * A failure is logged once, and so is the recovery after it, rather than on every attempt.
     */
    private function publish(): void
    {
        if ($this->snapshotPublisher === null) {
            return;
        }

        try {
            $this->snapshotPublisher->publish();
        } catch (MetricsSnapshotException $e) {
            $this->reportSnapshotFailed($e);

            return;
        }

        $this->reportSnapshotRecovered();
    }

    private function reportSnapshotFailed(MetricsSnapshotException $e): void
    {
        if ($this->isSnapshotFailing) {
            return;
        }

        $this->isSnapshotFailing = true;
        $this->logger?->warning(
            'Publishing the metrics snapshot failed.',
            ['pid' => getmypid()] + ExceptionLogging::makeLogContext($e),
        );
    }

    private function reportSnapshotRecovered(): void
    {
        if (!$this->isSnapshotFailing) {
            return;
        }

        $this->isSnapshotFailing = false;
        $this->logger?->info(
            'Publishing the metrics snapshot recovered.',
            ['pid' => getmypid()],
        );
    }
}
