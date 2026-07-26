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
use FreeDSx\Ldap\Server\ServerRunner\CoroutineServerRunnerInterface;

use function extension_loaded;

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
        if (!extension_loaded('swoole')) {
            throw new RuntimeException('The Swoole extension is required to use the Swoole ServerRunner.');
        }

        $this->worker = $workers->make();
    }

    public function run(): void
    {
        $this->worker->run();
    }
}
