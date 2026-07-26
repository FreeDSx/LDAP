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

use Closure;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Config\RunnerConfig;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use Psr\Log\LoggerInterface;

/**
 * The config a server needs to accept connections (network/TLS, auth-gating, logging, runner, metrics), shared by
 * ServerOptions and ProxyServerOptions.
 *
 * @api
 */
interface ServerListenerOptionsInterface
{
    public function getNetworkConfig(): NetworkConfig;

    public function isRequireAuthentication(): bool;

    public function isAllowAnonymous(): bool;

    /**
     * @return string[]
     */
    public function getSaslMechanisms(): array;

    public function getLogger(): ?LoggerInterface;

    public function getEventLogPolicy(): EventLogPolicy;

    public function getRunnerConfig(): RunnerConfig;

    public function isRunnerMode(RunnerMode $mode): bool;

    public function isMonitorEnabled(): bool;

    public function getMonitorSnapshotPath(): string;

    public function getMetricsRecorder(): MetricsRecorderInterface;

    public function getOnServerReady(): ?Closure;
}
