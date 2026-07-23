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

use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\ServerOptions;
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
        private readonly ServerOptions $options,
        private readonly ?LoggerInterface $logger,
    ) {}

    public function makeAndBind(): SocketServer
    {
        $isUnixSocket = $this->options->getTransport() === 'unix';
        $resource = $isUnixSocket
            ? $this->options->getUnixSocket()
            : $this->options->getIp();

        if ($isUnixSocket) {
            $this->removeExistingSocketIfNeeded($resource);
        }

        $writeTimeoutEnforcer = $this->options->getRunner() === RunnerMode::Swoole
            ? new SwooleTimerEnforcer()
            : new BlockingSelectEnforcer();

        $socketServerOptions = (new SocketServerOptions())
            ->setTransport(Transport::from($this->options->getTransport()))
            ->setIdleTimeout($this->options->getIdleTimeout())
            ->setWriteTimeout($this->options->getWriteTimeout())
            ->setWriteTimeoutEnforcer($writeTimeoutEnforcer)
            ->setUseSsl($this->options->isUseSsl())
            ->setSslCert($this->options->getSslCert())
            ->setSslCertKey($this->options->getSslCertKey())
            ->setSslCertPassphrase($this->options->getSslCertPassphrase())
            ->setSslCryptoMethod($this->options->getMinTlsVersion()->toServerCryptoMethod())
            ->setSslCiphers($this->options->getSslCiphers())
            ->setSslValidateCert($this->options->isSslValidateCert())
            ->setSslAllowSelfSigned($this->options->getSslAllowSelfSigned())
            ->setSslCaCert($this->options->getSslCaCert());

        return SocketServer::bind(
            $resource,
            $isUnixSocket
                ? null
                : $this->options->getPort(),
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
