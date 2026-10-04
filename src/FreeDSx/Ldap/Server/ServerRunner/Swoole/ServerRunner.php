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

use FreeDSx\Ldap\Server\ServerRunner\CoroutineServerRunnerInterface;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\Shared\ConnectionSlots;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\Shared\ReloadState;

/**
 * A server runner that uses Swoole coroutines.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerRunner implements CoroutineServerRunnerInterface
{
    private Worker $worker;

    public function __construct(WorkerFactory $workers)
    {
        $this->worker = $workers->make(
            new ConnectionSlots(),
            new ReloadState(),
        );
    }

    public function run(): void
    {
        $this->worker->run();
    }
}
