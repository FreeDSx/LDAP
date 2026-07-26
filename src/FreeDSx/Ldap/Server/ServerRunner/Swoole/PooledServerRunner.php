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

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use FreeDSx\Ldap\Server\ServerRunner\CoroutineServerRunnerInterface;
use Swoole\Process;
use Swoole\Process\Pool;

use function extension_loaded;

/**
 * Runs the coroutine accept loop in a pool of worker processes.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PooledServerRunner implements CoroutineServerRunnerInterface
{
    /**
     * Background tasks run in this worker alone.
     */
    private const OWNER_WORKER_ID = 0;

    /**
     * @param ?ResettableInterface $resettable Dropped in each worker, so none keeps a connection made before the fork.
     */
    public function __construct(
        private readonly WorkerFactory $workerFactory,
        private readonly int $workers,
        private readonly ?ResettableInterface $resettable = null,
    ) {
        if (!extension_loaded('swoole')) {
            throw new RuntimeException('The Swoole extension is required to use the Swoole PooledServerRunner.');
        }

        if ($this->workers < 2) {
            throw new RuntimeException('A worker pool needs more than one worker.');
        }
    }

    public function run(): void
    {
        $pool = new Pool($this->workers);

        $pool->on(
            'WorkerStart',
            fn(Pool $pool, int $workerId): null => $this->runWorker($workerId),
        );

        // The pool reloads on SIGUSR1 and leaves SIGHUP unhandled, which would terminate the master and orphan
        // every worker. Registering here only suppresses that default, since the master never dispatches it.
        Process::signal(
            SIGHUP,
            static fn(): null => null,
        );

        $pool->start();
    }

    private function runWorker(int $workerId): null
    {
        $this->resettable?->reset();

        $this->workerFactory
            ->make($workerId === self::OWNER_WORKER_ID)
            ->run(['worker_id' => $workerId]);

        return null;
    }
}
