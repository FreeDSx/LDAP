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

namespace FreeDSx\Ldap\Server\Proxy;

use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\NoticeOfDisconnectException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Utility\ExponentialBackoff;
use SensitiveParameter;

/**
 * Owns the identity of the upstream connection backing one proxied session.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ProxyUpstreamSession
{
    private bool $isBound = false;

    public function __construct(
        private readonly LdapClient $client,
        private readonly bool $useStartTls = false,
        private readonly SleeperInterface $sleeper = new BlockingSleeper(),
        private readonly int $maxAttempts = 3,
        private readonly ExponentialBackoff $backoff = new ExponentialBackoff(
            base: 0.05,
            max: 1.0,
        ),
    ) {}

    /**
     * Whether an identity is currently established upstream.
     */
    public function isBound(): bool
    {
        return $this->isBound;
    }

    /**
     * Establishes the identity upstream, reissuing only failures that prove the credential never landed.
     *
     * @throws BindException
     * @throws ConnectionException
     */
    public function bind(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): void {
        $attempt = 0;

        while (true) {
            try {
                $this->connectAndBind(
                    $name,
                    $password,
                );
                $this->isBound = true;

                return;
            } catch (ConnectionException $e) {
                $attempt++;

                if (!$this->canRetry($e, $attempt)) {
                    throw $e;
                }

                $this->sleeper->sleep($this->backoff->delayFor($attempt));
            }
        }
    }

    /**
     * Upgrades the upstream link before anything crosses it.
     *
     * @throws ConnectionException
     */
    public function ensureEncrypted(): void
    {
        // Re-issuing it on a connection already upgraded is an operations error the upstream answers by hanging up.
        if (!$this->useStartTls || $this->client->isEncrypted()) {
            return;
        }

        $this->client->startTls();
    }

    /**
     * Ends the upstream session so it cannot keep serving an identity the proxy no longer holds.
     */
    public function reset(): void
    {
        if (!$this->isBound) {
            return;
        }

        $this->isBound = false;

        if (!$this->client->isConnected()) {
            return;
        }

        try {
            $this->client->unbind();
        } catch (ConnectionException) {
            $this->client->disconnect();
        }
    }

    /**
     * Only a true transport failure is worth retrying.
     */
    private function canRetry(
        ConnectionException $exception,
        int $attempt,
    ): bool {
        return !$exception instanceof NoticeOfDisconnectException
            && $attempt < $this->maxAttempts;
    }

    /**
     * @throws BindException
     * @throws ConnectionException
     */
    private function connectAndBind(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): void {
        $this->ensureEncrypted();

        $this->client->bind(
            $name,
            $password,
        );
    }
}
