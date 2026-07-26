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

use Closure;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\Process\BackgroundTask\BackgroundTasksInterface;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Ldap\ServerListenerOptionsInterface;

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
     * @param Closure(ServerListenerOptionsInterface): ServerProtocolFactoryInterface $protocolFactoryProvider
     */
    public function __construct(
        private ServerProtocolFactoryInterface $serverProtocolFactory,
        private ServerListenerOptionsInterface $options,
        private SocketServerFactory $socketServerFactory,
        private Closure $protocolFactoryProvider,
        private MetricsRecorderInterface $metricsRecorder = new NullMetricsRecorder(),
        private ?BackgroundTasksInterface $backgroundTasks = null,
    ) {}

    /**
     * @param bool $withBackgroundTasks Only one worker may run them, since they must run once per server.
     */
    public function make(bool $withBackgroundTasks = true): Worker
    {
        return new Worker(
            $this->serverProtocolFactory,
            $this->options,
            $this->socketServerFactory,
            $this->protocolFactoryProvider,
            $this->metricsRecorder,
            $withBackgroundTasks
                ? $this->backgroundTasks
                : null,
        );
    }
}
