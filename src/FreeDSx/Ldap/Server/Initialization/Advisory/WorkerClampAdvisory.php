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

namespace FreeDSx\Ldap\Server\Initialization\Advisory;

use FreeDSx\Ldap\Server\Initialization\AdvisoryInterface;
use FreeDSx\Ldap\Server\Initialization\InitializationWarning;
use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\ServerListenerOptionsInterface;

/**
 * Several Swoole workers are clamped to one when the server keeps state that cannot be shared between processes.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class WorkerClampAdvisory implements AdvisoryInterface
{
    public function __construct(
        private ServerListenerOptionsInterface $options,
        private bool $supportsMultipleWorkers,
    ) {}

    public function warnings(): array
    {
        if (!$this->options->isRunnerMode(RunnerMode::Swoole) || $this->supportsMultipleWorkers) {
            return [];
        }

        $requestedWorkers = $this->options->getRunnerConfig()->resolvedWorkers();
        if ($requestedWorkers === 1) {
            return [];
        }

        return [
            InitializationWarning::concurrencyLimited(
                ConcurrencyLimitReason::StorageNotShareable,
                ['requested_workers' => $requestedWorkers],
            ),
        ];
    }
}
