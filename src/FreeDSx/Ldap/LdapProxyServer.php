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

namespace FreeDSx\Ldap;

use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Socket\Exception\ConnectionException;

/**
 * An LDAP server that forwards client requests to an upstream server.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class LdapProxyServer
{
    private readonly Container $container;

    public function __construct(
        private readonly ProxyOptions $options,
        ?Container $container = null,
    ) {
        $this->container = $container ?? Container::forProxy($this->options);
    }

    /**
     * Runs the proxy server. Binds the socket and starts accepting client connections.
     *
     * @throws ConnectionException
     */
    public function run(): void
    {
        $this->container->get(ServerRunnerInterface::class)->run();
    }

    public function getOptions(): ProxyOptions
    {
        return $this->options;
    }
}
