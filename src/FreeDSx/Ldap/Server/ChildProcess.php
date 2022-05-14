<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server;

use FreeDSx\Socket\Socket;

class ChildProcess
{
    /**
     * @var int
     */
    private $pid;

    /**
     * @var Socket
     */
    private $socket;

    public function __construct(
        int $pid,
        Socket $socket
    ) {
        $this->pid = $pid;
        $this->socket = $socket;
    }

    public function getPid(): int
    {
        return $this->pid;
    }

    public function getSocket(): Socket
    {
        return $this->socket;
    }

    public function closeSocket(): void
    {
        $this->socket->close();
    }
}
