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

use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\Process\BackgroundTask\BackgroundTasksInterface;
use FreeDSx\Ldap\Server\ServerRunner\RunnerConfiguration;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\Shared\ConnectionSlots;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\Shared\ReloadState;
use FreeDSx\Ldap\Server\SocketServerFactory;

/**
 * Builds the coroutine workers a runner serves on, after any fork so nothing is inherited.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class WorkerFactory
{
    /**
     * @param RunnerConfiguration $configuration Each worker process changes only its own copy, made by the fork.
     */
    public function __construct(
        private RunnerConfiguration $configuration,
        private SocketServerFactory $socketServerFactory,
        private MetricsRecorderInterface $metricsRecorder = new NullMetricsRecorder(),
        private ?BackgroundTasksInterface $backgroundTasks = null,
    ) {}

    /**
     * @param ConnectionSlots $connectionSlots Shared by every worker of the server.
     * @param ReloadState $reloadState Shared by every worker of the server.
     * @param int $workerId The pool's id for the worker; 0 for a single process.
     * @param bool $withBackgroundTasks Only one worker may run them, since they must run once per server.
     */
    public function make(
        ConnectionSlots $connectionSlots,
        ReloadState $reloadState,
        int $workerId = 0,
        bool $withBackgroundTasks = true,
    ): Worker {
        return new Worker(
            new WorkerConfiguration(
                $this->configuration,
                $reloadState,
            ),
            $this->socketServerFactory,
            $connectionSlots,
            $this->metricsRecorder,
            $withBackgroundTasks
                ? $this->backgroundTasks
                : null,
            $workerId,
        );
    }
}
