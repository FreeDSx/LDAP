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
use FreeDSx\Ldap\Server\Clock\Sleeper\BackoffSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Logging\ExceptionLogging;
use FreeDSx\Ldap\Server\Process\Signals\ShutdownSignalsInterface;
use Psr\Log\LoggerInterface;

/**
 * Runs the password-policy forwarder on a loop, sleeping the poll interval and backing off when the primary is down.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PasswordPolicyForwardWorker
{
    public const TASK_NAME = 'password-policy-forward';

    public const DEFAULT_INTERVAL_SECONDS = 5.0;

    private bool $stopping = false;

    public function __construct(
        private readonly PasswordPolicyForwarder $forwarder,
        private readonly SleeperInterface $sleeper,
        private readonly BackoffSleeper $backoff,
        private readonly float $interval = self::DEFAULT_INTERVAL_SECONDS,
        private readonly ?ShutdownSignalsInterface $signals = null,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    /**
     * Drain the queue until stopped, sleeping the poll interval between drains and backing off on delivery failure.
     */
    public function run(): void
    {
        $this->signals?->onShutdown($this->stop(...));

        while (!$this->stopping) {
            try {
                $this->forwarder->forwardOnce();
                $this->backoff->reset();
                $this->sleeper->sleep($this->interval);
            } catch (ForwardStateException $e) {
                $this->logger?->warning(
                    'Password-policy forwarding failed; retrying after backoff.',
                    ExceptionLogging::makeLogContext($e) + ['backoff_seconds' => $this->backoff->delay()],
                );
                $this->backoff->wait();
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
}
