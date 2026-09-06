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

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Socket\SocketServer;
use FreeDSx\Socket\SocketServerOptions;
use FreeDSx\Socket\Timeout\BlockingSelectEnforcer;
use FreeDSx\Socket\Timeout\SwooleTimerEnforcer;
use FreeDSx\Socket\Transport;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

class SocketServerFactory
{
    public function __construct(
        private readonly NetworkConfig $network,
        private readonly RunnerMode $runner,
        private readonly ?LoggerInterface $logger,
        private readonly bool $reusePort = false,
    ) {}

    /**
     * Whether the handler that owns a connection must negotiate TLS itself, rather than the listener doing it as part
     * of accepting.
     *
     * A session negotiated in the accept loop is inherited by every connection forked after it, and the first of those
     * to exit sends the close alert that ends the connection for the handler that actually owns it.
     */
    public function isTlsHandshakeDeferred(): bool
    {
        return $this->runner === RunnerMode::Pcntl
            && $this->network->isUseSsl()
            && Transport::from($this->network->getTransport()) === Transport::Tcp;
    }

    public function makeAndBind(): SocketServer
    {
        $isUnixSocket = $this->network->isUnixSocket();
        $resource = $isUnixSocket
            ? $this->network->getUnixSocket()
            : $this->network->getIp();

        if ($isUnixSocket) {
            $this->removeExistingSocketIfNeeded($resource);
        }

        $writeTimeoutEnforcer = $this->runner === RunnerMode::Swoole
            ? new SwooleTimerEnforcer()
            : new BlockingSelectEnforcer();

        $socketServerOptions = (new SocketServerOptions())
            ->setTransport(Transport::from($this->network->getTransport()))
            ->setIdleTimeout($this->network->getIdleTimeout())
            ->setWriteTimeout($this->network->getWriteTimeout())
            ->setWriteTimeoutEnforcer($writeTimeoutEnforcer)
            ->setUseSsl($this->network->isUseSsl() && !$this->isTlsHandshakeDeferred())
            ->setSslCert($this->network->getSslCert())
            ->setSslCertKey($this->network->getSslCertKey())
            ->setSslCertPassphrase($this->network->getSslCertPassphrase())
            ->setSslCryptoMethod($this->network->getMinTlsVersion()->toServerCryptoMethod())
            ->setSslCiphers($this->network->getSslCiphers())
            ->setSslValidateCert($this->network->isSslValidateCert())
            // Swoole does not support populating the peer certificate. Asking for one breaks StartTLS.
            ->setSslCapturePeerCert($this->runner !== RunnerMode::Swoole)
            ->setSslAllowSelfSigned($this->network->getSslAllowSelfSigned())
            ->setSslCaCert($this->network->getSslCaCert())
            ->setReusePort($this->reusePort);

        return SocketServer::bind(
            $resource,
            $isUnixSocket
                ? null
                : $this->network->getPort(),
            $socketServerOptions,
        );
    }

    private function removeExistingSocketIfNeeded(string $socket): void
    {
        if (!file_exists($socket)) {
            return;
        }

        if (!is_writeable($socket)) {
            $message = sprintf(
                'The socket "%s" already exists and is not writeable. To run the LDAP server, you must remove the existing socket.',
                $socket,
            );
            $this->logger?->log(LogLevel::ERROR, $message);

            throw new RuntimeException($message);
        }

        if (!unlink($socket)) {
            $message = sprintf(
                'The existing socket "%s" could not be removed. To run the LDAP server, you must remove the existing socket.',
                $socket,
            );
            $this->logger?->log(LogLevel::ERROR, $message);

            throw new RuntimeException($message);
        }
    }
}
