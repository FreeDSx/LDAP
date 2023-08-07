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

namespace FreeDSx\Ldap\Server;

use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\SocketServer;
use Psr\Log\LoggerInterface;

class SocketServerFactory
{
    use LoggerTrait;

    public function __construct(
        private readonly ServerOptions $options,
        private readonly ?LoggerInterface $logger,
    ) {
    }

    public function makeAndBind(): SocketServer
    {
        $isUnixSocket = $this->options->getTransport() === 'unix';
        $resource = $isUnixSocket
            ? $this->options->getUnixSocket()
            : $this->options->getIp();

        if ($isUnixSocket) {
            $this->removeExistingSocketIfNeeded($resource);
        }

        return SocketServer::bind(
            $resource,
            $this->options->getPort(),
            $this->options->toArray(),
        );
    }

    private function removeExistingSocketIfNeeded(string $socket): void
    {
        if (!file_exists($socket)) {
            return;
        }

        if (!is_writeable($socket)) {
            $this->logAndThrow(sprintf(
                'The socket "%s" already exists and is not writeable. To run the LDAP server, you must remove the existing socket.',
                $socket
            ));
        }

        if (!unlink($socket)) {
            $this->logAndThrow(sprintf(
                'The existing socket "%s" could not be removed. To run the LDAP server, you must remove the existing socket.',
                $socket
            ));
        }
    }
}
