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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward;

use FreeDSx\Ldap\Exception\ForwardStateException;
use FreeDSx\Ldap\Exception\ForwardStateRejectedException;
use FreeDSx\Ldap\Operation\Request\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Logging\ExceptionLogging;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaForwardState;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\Process\Signals\ShutdownSignalsInterface;
use FreeDSx\Ldap\Sync\Consumer\ReconnectBackoff;
use Psr\Log\LoggerInterface;

/**
 * Drains the replica-local password-policy forward queue on a loop, delivering each pending subject's state to the
 * primary over a reused connection and backing off when the primary is unreachable.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PasswordPolicyForwardWorker
{
    public const TASK_NAME = 'password-policy-forward';

    public const DEFAULT_INTERVAL_SECONDS = 5.0;

    private bool $stopping = false;

    private int $drain = 0;

    /**
     * @var array<string, RefusedForward>
     */
    private array $refused = [];

    public function __construct(
        private readonly ReplicaPasswordStateStoreInterface $store,
        private readonly ForwardStateSenderInterface $sender,
        private readonly SleeperInterface $sleeper,
        private readonly float $interval = self::DEFAULT_INTERVAL_SECONDS,
        private readonly ReconnectBackoff $backoff = new ReconnectBackoff(),
        private readonly ?ShutdownSignalsInterface $signals = null,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    /**
     * Drain the queue until stopped, sleeping the poll interval between drains and backing off on delivery failure.
     */
    public function run(): void
    {
        $this->signals?->onShutdown($this->stop(...));

        $delay = $this->backoff->initial();

        while (!$this->stopping) {
            try {
                $this->forwardOnce();
                $delay = $this->backoff->initial();
                $this->sleeper->sleep($this->interval);
            } catch (ForwardStateException $e) {
                $this->logger?->warning(
                    'Password-policy forwarding failed; retrying after backoff.',
                    ExceptionLogging::makeLogContext($e) + ['backoff_seconds' => $delay],
                );
                $this->sleeper->sleep($delay);
                $delay = $this->backoff->next($delay);
            }
        }
    }

    /**
     * Stop the loop; safe to call from a signal handler or another coroutine.
     */
    public function stop(): void
    {
        $this->stopping = true;
    }

    /**
     * Forward every pending subject in watermark order, advancing the watermark after each successful delivery; a
     * delivery failure stops the drain so the remainder stays pending for the next run.
     *
     * @return int the number of subjects forwarded
     * @throws ForwardStateException
     */
    public function forwardOnce(): int
    {
        $forwarded = 0;
        $refused = [];
        ++$this->drain;

        foreach ($this->store->listUnforwarded() as $pending) {
            $key = self::keyFor($pending);
            $previous = $this->refusalFor($pending);

            if ($previous !== null && !$previous->isDue($this->drain)) {
                $refused[$key] = $previous;

                continue;
            }

            try {
                $this->sender->send($this->requestFor($pending));
            } catch (ForwardStateRejectedException $e) {
                // One subject the primary refuses must not hold back every other subject behind it.
                $this->reportRefusal($pending, $previous, $e);
                $refused[$key] = $previous?->again($this->drain)
                    ?? RefusedForward::after($pending->sequence, $this->drain);

                continue;
            }

            $this->store->markForwarded(
                $pending->dn,
                $pending->sequence,
            );
            ++$forwarded;
        }

        $this->refused = $refused;

        return $forwarded;
    }

    /**
     * The standing refusal for this subject, or null when its state has moved on and deserves a fresh attempt.
     */
    private function refusalFor(ReplicaForwardState $pending): ?RefusedForward
    {
        $refusal = $this->refused[self::keyFor($pending)] ?? null;

        return $refusal?->sequence === $pending->sequence
            ? $refusal
            : null;
    }

    /**
     * Normalized, so one subject cannot occupy two entries under two spellings of its DN.
     */
    private static function keyFor(ReplicaForwardState $pending): string
    {
        return $pending->dn
            ->normalize()
            ->toString();
    }

    /**
     * Reported once per subject state to avoid logging this indefinitely.
     */
    private function reportRefusal(
        ReplicaForwardState $pending,
        ?RefusedForward $previous,
        ForwardStateRejectedException $exception,
    ): void {
        if ($previous !== null) {
            return;
        }

        $this->logger?->warning(
            'The primary refused a password-policy forward; leaving it pending and continuing.',
            ExceptionLogging::makeLogContext($exception) + ['dn' => $pending->dn->toString()],
        );
    }

    private function requestFor(ReplicaForwardState $pending): ForwardPasswordPolicyStateRequest
    {
        $state = $pending->state->toUserPasswordState($pending->dn);

        return new ForwardPasswordPolicyStateRequest(
            $pending->dn,
            failureTimes: $state->failureTimes,
            lastSuccess: $state->lastSuccess,
        );
    }
}
