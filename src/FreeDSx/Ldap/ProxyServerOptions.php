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

use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Config\RunnerConfig;

/**
 * The forwarding proxy's own server config (its listener, TLS, auth-gating, logging, runner), separate from the upstream
 * connection held on ProxyOptions.
 *
 * @api
 */
final class ProxyServerOptions implements ServerListenerOptionsInterface
{
    use ServerListenerOptionsTrait;

    public function __construct(
        ?NetworkConfig $network = null,
        ?RunnerConfig $runner = null,
    ) {
        $this->network = $network ?? new NetworkConfig();
        $this->runner = $runner ?? new RunnerConfig();
    }

    /**
     * A proxy performs simple and anonymous binds only; SASL is never advertised.
     *
     * @return string[]
     */
    public function getSaslMechanisms(): array
    {
        return [];
    }
}
