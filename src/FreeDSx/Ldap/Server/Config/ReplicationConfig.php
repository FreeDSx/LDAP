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

namespace FreeDSx\Ldap\Server\Config;

use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Config\Replication\ConsumerConfig;
use FreeDSx\Ldap\Server\Config\Replication\ProviderConfig;

/**
 * The replication role a server plays, and its identity within the topology.
 *
 * Note: Serving sync from a consumer is not supported.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ReplicationConfig
{
    public function __construct(
        private ReplicaId $id = new ReplicaId(),
        private ?ProviderConfig $provider = null,
        private ?ConsumerConfig $consumer = null,
    ) {}

    /**
     * A primary that serves sync to downstream consumers.
     */
    public static function forProvider(?ProviderConfig $provider = null): self
    {
        return new self(provider: $provider ?? new ProviderConfig());
    }

    /**
     * A read-only replica that mirrors an upstream primary.
     */
    public static function forReplica(ConsumerConfig $consumer): self
    {
        return new self(consumer: $consumer);
    }

    /**
     * This server's identity, stamped on the changes it authors and carried in the sync cookie.
     */
    public function getId(): ReplicaId
    {
        return $this->id;
    }

    public function setId(ReplicaId $id): self
    {
        $this->id = $id;

        return $this;
    }

    public function getProvider(): ?ProviderConfig
    {
        return $this->provider;
    }

    public function setProvider(?ProviderConfig $provider): self
    {
        $this->provider = $provider;

        return $this;
    }

    public function getConsumer(): ?ConsumerConfig
    {
        return $this->consumer;
    }

    public function setConsumer(?ConsumerConfig $consumer): self
    {
        $this->consumer = $consumer;

        return $this;
    }

    /**
     * Whether this server serves sync to downstream consumers.
     */
    public function isProvider(): bool
    {
        return $this->provider !== null;
    }

    /**
     * Whether this server mirrors an upstream primary.
     */
    public function isConsumer(): bool
    {
        return $this->consumer !== null;
    }
}
