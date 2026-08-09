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

namespace FreeDSx\Ldap\Sync\Consumer;

use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Server\Config\Replication\ConsumerConfig;
use FreeDSx\Ldap\Sync\SyncRepl;

/**
 * Opens an authenticated connection to the primary using the replica's sync identity (StartTLS then bind).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class PrimaryConnectionFactory
{
    public function __construct(private ConsumerConfig $config) {}

    public function connectLdapClient(): LdapClient
    {
        $client = new LdapClient($this->config->getPrimary());

        if ($this->config->getUseStartTls()) {
            $client->startTls();
        }

        $bind = $this->config->getBind();
        if ($bind !== null) {
            $client->sendAndReceive($bind);
        }

        return $client;
    }

    public function connectSyncRepl(): SyncRepl
    {
        return $this->connectLdapClient()
            ->syncRepl($this->config->getFilter());
    }
}
