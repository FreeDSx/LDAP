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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal;

use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Observation\JournalObservation;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use Throwable;

use function microtime;

/**
 * Prunes the change journal per its retention policy, emitting a structured event with the outcome.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class RetentionSweeper
{
    public const TASK_NAME = 'retention-sweep';

    public const DEFAULT_INTERVAL_SECONDS = 60.0;

    public function __construct(
        private ChangeJournalInterface $journal,
        private RetentionPolicy $policy,
        private EventLogger $eventLogger = new EventLogger(null),
        private MetricsRecorderInterface $metricsRecorder = new NullMetricsRecorder(),
    ) {}

    /**
     * A sweep is warranted only when the policy sets a limit and the journal is observable by the sweeping process.
     */
    public static function isSweepable(
        RetentionPolicy $policy,
        ChangeJournalInterface $journal,
        bool $singleProcess,
    ): bool {
        return $policy->hasLimits()
            && ($singleProcess || $journal->sharesAcrossProcesses());
    }

    /**
     * Prune once.
     *
     * @return int The number of records removed (0 on failure).
     */
    public function sweep(): int
    {
        $startedAt = microtime(true);

        try {
            $removed = $this->journal->prune($this->policy);
        } catch (Throwable $e) {
            $this->metricsRecorder->journalObserved(JournalObservation::PruneFailed);
            $this->eventLogger->record(
                ServerEvent::JournalPruneFailed,
                $this->eventLogger->exceptionContextFor($e),
            );

            return 0;
        }

        $this->metricsRecorder->journalObserved(JournalObservation::PruneSucceeded);

        if ($removed > 0) {
            $this->eventLogger->record(
                ServerEvent::JournalPruned,
                [
                    EventContext::REMOVED => $removed,
                    EventContext::DURATION_SECONDS => microtime(true) - $startedAt,
                ],
            );
        }

        return $removed;
    }
}
