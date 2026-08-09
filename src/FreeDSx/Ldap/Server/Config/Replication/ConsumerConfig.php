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

namespace FreeDSx\Ldap\Server\Config\Replication;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Sync\Consumer\Checkpoint\InMemoryReplicationCheckpoint;
use FreeDSx\Ldap\Sync\Consumer\Checkpoint\ReplicationCheckpointInterface;
use FreeDSx\Ldap\Sync\Consumer\ReconnectBackoff;

/**
 * How a server mirrors an upstream primary over RFC 4533.
 *
 * Consumers currently act as read-only.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ConsumerConfig
{
    /**
     * Seconds between drains of the queue forwarding local bind state to the primary.
     */
    public const DEFAULT_FORWARD_INTERVAL = 5.0;

    private float $forwardInterval = self::DEFAULT_FORWARD_INTERVAL;

    private ?ReconnectBackoff $reconnectBackoff = null;

    public function __construct(
        private readonly ClientOptions $primary,
        private readonly ReplicationCheckpointInterface $checkpoint = new InMemoryReplicationCheckpoint(),
        private ?FilterInterface $filter = null,
        private bool $referWrites = true,
        private ?BindRequest $bind = null,
        private bool $useStartTls = false,
    ) {}

    /**
     * The client options for connecting to the upstream primary (servers, LDAPS/mTLS, base DN).
     */
    public function getPrimary(): ClientOptions
    {
        return $this->primary;
    }

    /**
     * How the consumer authenticates to the primary (via Operations::bind() or Operations::bindSasl()), or null for none.
     */
    public function getBind(): ?BindRequest
    {
        return $this->bind;
    }

    public function setBind(BindRequest $bind): self
    {
        $this->bind = $bind;

        return $this;
    }

    /**
     * Whether the consumer issues StartTLS on the primary connection before binding (LDAPS is set on the primary options).
     */
    public function getUseStartTls(): bool
    {
        return $this->useStartTls;
    }

    public function setUseStartTls(bool $useStartTls): self
    {
        $this->useStartTls = $useStartTls;

        return $this;
    }

    /**
     * How long queued bind state waits before the next attempt to forward it to the primary.
     */
    public function getForwardInterval(): float
    {
        return $this->forwardInterval;
    }

    /**
     * @throws InvalidArgumentException when the interval is not positive, which would drain without pause.
     */
    public function setForwardInterval(float $forwardInterval): self
    {
        if ($forwardInterval <= 0) {
            throw new InvalidArgumentException('The forward interval must be greater than zero.');
        }

        $this->forwardInterval = $forwardInterval;

        return $this;
    }

    /**
     * The bounded backoff applied between reconnect attempts to the primary.
     */
    public function getReconnectBackoff(): ReconnectBackoff
    {
        return $this->reconnectBackoff ??= new ReconnectBackoff();
    }

    public function setReconnectBackoff(ReconnectBackoff $reconnectBackoff): self
    {
        $this->reconnectBackoff = $reconnectBackoff;

        return $this;
    }

    /**
     * Where the sync cookie is persisted so the consumer resumes across restarts.
     */
    public function getCheckpoint(): ReplicationCheckpointInterface
    {
        return $this->checkpoint;
    }

    /**
     * The filter selecting which entries to replicate, or null for all in-scope entries.
     */
    public function getFilter(): ?FilterInterface
    {
        return $this->filter;
    }

    public function setFilter(?FilterInterface $filter): self
    {
        $this->filter = $filter;

        return $this;
    }

    /**
     * Whether a client write is referred to the primary (true) or hard-rejected (false).
     */
    public function shouldReferWrites(): bool
    {
        return $this->referWrites;
    }

    public function setReferWrites(bool $referWrites): self
    {
        $this->referWrites = $referWrites;

        return $this;
    }

    /**
     * The primary's LDAP URLs, for referring client writes upstream.
     *
     * @return list<LdapUrl>
     */
    public function referralUrls(): array
    {
        $urls = [];

        foreach ($this->primary->getServers() as $server) {
            $urls[] = (new LdapUrl($server))
                ->setPort($this->primary->getPort())
                ->setUseSsl($this->primary->isUseSsl());
        }

        return $urls;
    }
}
