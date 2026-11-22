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

namespace FreeDSx\Ldap\Server\ServerRunner\Swoole;

use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\ServerListenerOptionsInterface;

/**
 * How many workers a Swoole server accepts on, and what limits it to one when several are configured.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class WorkerLimit
{
    public function __construct(
        private ServerListenerOptionsInterface $options,
        private bool $backendSupportsMultipleWorkers,
    ) {}

    /**
     * The configured count with auto-detection applied, or one when something limits it.
     */
    public function workers(): int
    {
        if (!$this->options->isRunnerMode(RunnerMode::Swoole) || $this->reason() !== null) {
            return 1;
        }

        return $this->requested();
    }

    /**
     * What limits several configured workers to one, with the storage taking precedence over the transport.
     */
    public function reason(): ?ConcurrencyLimitReason
    {
        if (!$this->options->isRunnerMode(RunnerMode::Swoole) || $this->requested() === 1) {
            return null;
        }
        if (!$this->backendSupportsMultipleWorkers) {
            return ConcurrencyLimitReason::StorageNotShareable;
        }
        // Each worker binds the path anew, leaving only the last worker's socket reachable.
        if ($this->options->getNetworkConfig()->isUnixSocket()) {
            return ConcurrencyLimitReason::UnixSocket;
        }

        return null;
    }

    /**
     * The configured count with auto-detection applied.
     */
    public function requested(): int
    {
        return $this->options->getRunnerConfig()->resolvedWorkers();
    }
}
