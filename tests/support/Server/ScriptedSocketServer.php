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

namespace Tests\Support\FreeDSx\Ldap\Server;

use Closure;
use FreeDSx\Socket\Exception\AcceptException;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketServer;

/**
 * A listening server that hands out the given connections in order, throwing any accept failure among them.
 */
final class ScriptedSocketServer extends SocketServer
{
    /**
     * @param list<Socket|AcceptException> $arrivals
     * @param ?Closure(): void $onArrival Runs as each connection is accepted.
     * @param ?Closure(): void $onDrained Runs when an accept finds no connection left.
     */
    public function __construct(
        private array $arrivals,
        private readonly ?Closure $onArrival = null,
        private readonly ?Closure $onDrained = null,
    ) {
        parent::__construct();
    }

    public function accept(float $timeout = -1.0): ?Socket
    {
        $socket = array_shift($this->arrivals);

        if ($socket === null) {
            $this->onDrained?->__invoke();

            return null;
        }
        if ($socket instanceof AcceptException) {
            throw $socket;
        }
        $this->onArrival?->__invoke();
        $this->clients[] = $socket;

        return $socket;
    }
}
