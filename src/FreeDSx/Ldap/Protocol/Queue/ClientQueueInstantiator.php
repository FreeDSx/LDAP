<?php

declare(strict_types=1);

namespace FreeDSx\Ldap\Protocol\Queue;

use FreeDSx\Socket\SocketPool;

/**
 * This class is purely used to lazy-load / instantiate the queue. As when the queue loads we need to provide a socket.
 * The socket for the queue is instantiated from a socket pool, which initiates a connection. We want to delay that
 * connection until the queue is actually required for usage.
 */
class ClientQueueInstantiator
{
    private ?ClientQueue $clientQueue = null;

    public function __construct(private readonly SocketPool $socketPool)
    {
    }

    public function make(): ClientQueue
    {
        if ($this->clientQueue) {
            return $this->clientQueue;
        }
        $this->clientQueue = new ClientQueue($this->socketPool);

        return $this->clientQueue;
    }
}
