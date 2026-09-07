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

    public function __construct(private readonly SocketPool $socketPool) {}

    public function make(): ClientQueue
    {
        if ($this->clientQueue) {
            return $this->clientQueue;
        }
        $this->clientQueue = new ClientQueue($this->socketPool);

        return $this->clientQueue;
    }

    /**
     * This allows us to check if the queue has been instantiated and connected, as for some operations we do not want
     * to bother we if we never connected in the first place.
     */
    public function isInstantiatedAndConnected(): bool
    {
        return $this->clientQueue !== null
            && $this->clientQueue->isConnected();
    }

    /**
     * Whether the queue exists and its connection has been upgraded.
     */
    public function isInstantiatedAndEncrypted(): bool
    {
        return $this->clientQueue !== null
            && $this->clientQueue->isConnected()
            && $this->clientQueue->isEncrypted();
    }

    /**
     * Close the connection socket if the queue was instantiated. It will reconnect on next use.
     */
    public function close(): void
    {
        $this->clientQueue?->close();
    }
}
