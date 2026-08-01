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
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use Psr\Log\LoggerInterface;

/**
 * The listener config (network/TLS, auth-gating, logging, runner, metrics) shared by ServerOptions and
 * ProxyServerOptions; using classes initialize $networkConfig in their constructor.
 */
trait ServerListenerOptionsTrait
{
    private NetworkConfig $networkConfig;

    private bool $requireAuthentication = true;

    private bool $allowAnonymous = false;

    private ?LoggerInterface $logger = null;

    private ?EventLogPolicy $eventLogPolicy = null;

    private RunnerConfig $runnerConfig;

    private bool $monitorEnabled = false;

    private ?string $monitorSnapshotPath = null;

    private ?MetricsRecorderInterface $metricsRecorder = null;

    private ?Closure $onServerReady = null;

    public function getNetworkConfig(): NetworkConfig
    {
        return $this->networkConfig;
    }

    public function setNetworkConfig(NetworkConfig $networkConfig): self
    {
        $this->networkConfig = $networkConfig;

        return $this;
    }

    public function isRequireAuthentication(): bool
    {
        return $this->requireAuthentication;
    }

    public function setRequireAuthentication(bool $requireAuthentication): self
    {
        $this->requireAuthentication = $requireAuthentication;

        return $this;
    }

    public function isAllowAnonymous(): bool
    {
        return $this->allowAnonymous;
    }

    public function setAllowAnonymous(bool $allowAnonymous): self
    {
        $this->allowAnonymous = $allowAnonymous;

        return $this;
    }

    public function getLogger(): ?LoggerInterface
    {
        return $this->logger;
    }

    public function setLogger(?LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    public function getEventLogPolicy(): EventLogPolicy
    {
        return $this->eventLogPolicy ??= EventLogPolicy::default();
    }

    /**
     * @api
     */
    public function setEventLogPolicy(EventLogPolicy $policy): self
    {
        $this->eventLogPolicy = $policy;

        return $this;
    }

    public function setRunnerConfig(RunnerConfig $runnerConfig): self
    {
        $this->runnerConfig = $runnerConfig;

        return $this;
    }

    public function getRunnerConfig(): RunnerConfig
    {
        return $this->runnerConfig;
    }

    public function isRunnerMode(RunnerMode $mode): bool
    {
        return $this->runnerConfig->getMode() === $mode;
    }

    public function isMonitorEnabled(): bool
    {
        return $this->monitorEnabled;
    }

    public function setMonitorEnabled(bool $monitorEnabled): self
    {
        $this->monitorEnabled = $monitorEnabled;

        return $this;
    }

    /**
     * The configured cn=monitor snapshot path, or a per-port default under the system temp directory.
     */
    public function getMonitorSnapshotPath(): string
    {
        return $this->monitorSnapshotPath
            ?? sys_get_temp_dir() . '/freedsx_ldap_monitor_' . $this->networkConfig->getPort() . '.json';
    }

    public function setMonitorSnapshotPath(?string $monitorSnapshotPath): self
    {
        $this->monitorSnapshotPath = $monitorSnapshotPath;

        return $this;
    }

    public function getMetricsRecorder(): MetricsRecorderInterface
    {
        return $this->metricsRecorder ??= new NullMetricsRecorder();
    }

    public function setMetricsRecorder(MetricsRecorderInterface $metricsRecorder): self
    {
        $this->metricsRecorder = $metricsRecorder;

        return $this;
    }

    public function getOnServerReady(): ?Closure
    {
        return $this->onServerReady;
    }

    public function setOnServerReady(?Closure $onServerReady): self
    {
        $this->onServerReady = $onServerReady;

        return $this;
    }
}
