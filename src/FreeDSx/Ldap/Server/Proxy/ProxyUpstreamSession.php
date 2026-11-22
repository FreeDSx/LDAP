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
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ReferralException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Protocol\Session\SessionTeardownInterface;
use SensitiveParameter;

/**
 * Owns the identity of the upstream connection backing one proxied session.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ProxyUpstreamSession implements SessionTeardownInterface
{
    private bool $isBound = false;

    public function __construct(
        private readonly LdapClient $client,
        private readonly bool $useStartTls = false,
    ) {}

    /**
     * Unbinds and closes the upstream connection when one is open, without ever opening one.
     */
    public function tearDown(): void
    {
        $this->isBound = false;

        if (!$this->client->isConnected()) {
            return;
        }

        try {
            $this->client->unbind();
        } catch (ConnectionException|OperationException) {
            $this->client->disconnect();
        }
    }

    /**
     * Whether an identity is currently established upstream.
     */
    public function isBound(): bool
    {
        return $this->isBound;
    }

    /**
     * Establishes the identity upstream, sending the credential once since a failed send cannot prove it never landed.
     *
     * @throws BindException
     * @throws ConnectionException
     */
    public function bind(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): void {
        try {
            $this->ensureReady();
            $this->client->bind(
                $name,
                $password,
            );
        } catch (ConnectionException $e) {
            $this->dropConnection();

            throw $e;
        }

        $this->isBound = true;
    }

    /**
     * The authorization identity the upstream reports for this session, or null when it will not say.
     *
     * @throws ConnectionException
     */
    public function whoAmI(): ?string
    {
        try {
            return $this->client->whoami();
        } catch (OperationException|ReferralException) {
            return null;
        } catch (ConnectionException $e) {
            $this->dropConnection();

            throw $e;
        }
    }

    /**
     * Readies the upstream link before anything crosses it.
     *
     * @throws ConnectionException
     */
    public function ensureReady(): void
    {
        $isClosed = !$this->client->isConnected();

        if ($isClosed && $this->isBound) {
            throw new ConnectionException('The upstream connection backing the bound session was lost.');
        }
        if ($isClosed) {
            $this->client->disconnect();
        }

        // Re-issuing it on a connection already upgraded is an operations error the upstream answers by hanging up.
        if (!$this->useStartTls || $this->client->isEncrypted()) {
            return;
        }

        $this->client->startTls();
    }

    /**
     * Drops the upstream connection after a failed request, so a late reply cannot answer the next one.
     */
    public function dropConnection(): void
    {
        $this->client->disconnect();
    }

    /**
     * Ends the upstream session so it cannot keep serving an identity the proxy no longer holds.
     */
    public function reset(): void
    {
        if (!$this->isBound) {
            return;
        }

        $this->tearDown();
    }
}
