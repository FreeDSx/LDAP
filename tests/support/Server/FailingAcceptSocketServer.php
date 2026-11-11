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

use FreeDSx\Socket\Exception\AcceptException;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketServer;
use FreeDSx\Socket\SocketServerOptions;

use function stream_select;

/**
 * A listening server that fails its first accepts of a waiting client, leaving the client queued as a real failure does.
 */
final class FailingAcceptSocketServer extends SocketServer
{
    private const MICROSECONDS_PER_SECOND = 1_000_000;

    public function __construct(
        SocketServerOptions $options,
        private int $failingAccepts,
    ) {
        parent::__construct($options);
    }

    public function accept(float $timeout = -1.0): ?Socket
    {
        if ($this->failingAccepts === 0) {
            return parent::accept($timeout);
        }

        if (!$this->isClientWaiting($timeout)) {
            return null;
        }
        $this->failingAccepts--;

        throw new AcceptException('Unable to accept a waiting client: a scripted failure');
    }

    private function isClientWaiting(float $timeout): bool
    {
        if ($this->socket === null) {
            return false;
        }

        $read = [$this->socket];
        $write = null;
        $except = null;
        $isUnbounded = $timeout < 0;

        return @stream_select(
            $read,
            $write,
            $except,
            $isUnbounded ? null : (int) $timeout,
            $isUnbounded ? null : (int) (($timeout - (int) $timeout) * self::MICROSECONDS_PER_SECOND),
        ) > 0;
    }
}
