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

namespace FreeDSx\Ldap\Container\Provider;

use Closure;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Container\ContainerReloadFactory;
use FreeDSx\Ldap\Container\Contributor\ListenerContributorInterface;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\Metrics\File\FileSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\File\FileSnapshotWriter;
use FreeDSx\Ldap\Server\Metrics\File\SnapshotPublisher;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\MetricsSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Recorder\MetricsRecorderChain;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationRollupCoordinator;
use FreeDSx\Ldap\Server\Process\BackgroundTask\BackgroundTasksInterface;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\ServerRunner\PcntlServerRunner;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Server\ServerRunner\SwooleServerRunner;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Ldap\ServerListenerOptionsInterface;

/**
 * Registers the listener services shared by every server type: the socket, runner, reload, authorization, and metrics.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ServerListenerContainerProvider implements ContainerProviderInterface
{
    public function factories(): array
    {
        return [
            SocketServerFactory::class => $this->makeSocketServerFactory(...),
            ServerAuthorization::class => $this->makeServerAuthorizer(...),
            ServerRunnerInterface::class => $this->makeServerRunner(...),
            InMemoryMetricsRecorder::class => static fn(): InMemoryMetricsRecorder => new InMemoryMetricsRecorder(),
            MetricsRecorderInterface::class => $this->makeMetricsRecorder(...),
            MetricsSnapshotProvider::class => $this->makeMetricsSnapshotProvider(...),
            OperationRollupCoordinator::class => $this->makeOperationRollupCoordinator(...),
        ];
    }

    private function makeSocketServerFactory(Container $container): SocketServerFactory
    {
        $options = $container->get(ServerListenerOptionsInterface::class);

        return new SocketServerFactory(
            $options->getNetworkConfig(),
            $options->getRunner(),
            $options->getLogger(),
        );
    }

    private function makeServerAuthorizer(Container $container): ServerAuthorization
    {
        return new ServerAuthorization($container->get(ServerListenerOptionsInterface::class));
    }

    private function makeServerRunner(Container $container): ServerRunnerInterface
    {
        $options = $container->get(ServerListenerOptionsInterface::class);
        $protocolFactoryProvider = $this->makeProtocolFactoryProvider($container);
        $metricsRecorder = $container->get(MetricsRecorderInterface::class);

        if ($options->getRunner() === RunnerMode::Swoole) {
            return new SwooleServerRunner(
                serverProtocolFactory: $protocolFactoryProvider($options),
                options: $options,
                socketServerFactory: $container->get(SocketServerFactory::class),
                protocolFactoryProvider: $protocolFactoryProvider,
                metricsRecorder: $metricsRecorder,
                backgroundTasks: $container->get(BackgroundTasksInterface::class),
            );
        }

        return new PcntlServerRunner(
            serverProtocolFactory: $protocolFactoryProvider($options),
            options: $options,
            socketServerFactory: $container->get(SocketServerFactory::class),
            protocolFactoryProvider: $protocolFactoryProvider,
            metricsRecorder: $metricsRecorder,
            snapshotPublisher: $this->makeSnapshotPublisher($container),
            operationRollup: $this->makeOperationRollup($container),
            resettable: $container->get(ListenerContributorInterface::class)->forkResettable(),
            backgroundTasks: $container->get(BackgroundTasksInterface::class),
        );
    }

    /**
     * Builds a protocol factory from a (possibly reloaded) set of options via a freshly assembled container.
     *
     * @return Closure(ServerListenerOptionsInterface): ServerProtocolFactoryInterface
     */
    private function makeProtocolFactoryProvider(Container $container): Closure
    {
        $rebuild = $container->get(ContainerReloadFactory::class);
        $shared = $this->reloadSharedInstances($container);

        return static fn(ServerListenerOptionsInterface $options): ServerProtocolFactoryInterface => $rebuild
            ->rebuild($options, $shared)
            ->get(ServerProtocolFactoryInterface::class);
    }

    /**
     * Services carried verbatim across a SIGHUP reload so their live state survives into the fresh container.
     *
     * @return array<class-string, object>
     */
    private function reloadSharedInstances(Container $container): array
    {
        $shared = [
            MetricsRecorderInterface::class => $container->get(MetricsRecorderInterface::class),
            MetricsSnapshotProvider::class => $container->get(MetricsSnapshotProvider::class),
            InMemoryMetricsRecorder::class => $container->get(InMemoryMetricsRecorder::class),
        ];

        $operationRollup = $this->makeOperationRollup($container);
        if ($operationRollup !== null) {
            $shared[OperationRollupCoordinator::class] = $operationRollup;
        }

        return $shared + $container->get(ListenerContributorInterface::class)->reloadInstances();
    }

    /**
     * The child-to-parent operation rollup for the forking runner; built only when cn=monitor is enabled.
     */
    private function makeOperationRollup(Container $container): ?OperationRollupCoordinator
    {
        if (!$container->get(ServerListenerOptionsInterface::class)->isMonitorEnabled()) {
            return null;
        }

        return $container->get(OperationRollupCoordinator::class);
    }

    private function makeOperationRollupCoordinator(Container $container): OperationRollupCoordinator
    {
        return new OperationRollupCoordinator($container->get(InMemoryMetricsRecorder::class));
    }

    /**
     * The PCNTL parent publishes connection metrics to a file for forked children (serving cn=monitor); built only when
     * cn=monitor is enabled.
     */
    private function makeSnapshotPublisher(Container $container): ?SnapshotPublisher
    {
        $options = $container->get(ServerListenerOptionsInterface::class);

        if (!$options->isMonitorEnabled()) {
            return null;
        }

        return new SnapshotPublisher(
            $container->get(InMemoryMetricsRecorder::class),
            new FileSnapshotWriter($options->getMonitorSnapshotPath()),
        );
    }

    /**
     * The process metrics recorder: an in-memory recorder when cn=monitor is enabled (chained with a user recorder if
     * set), otherwise just the user recorder (a no-op by default).
     */
    private function makeMetricsRecorder(Container $container): MetricsRecorderInterface
    {
        $options = $container->get(ServerListenerOptionsInterface::class);
        $userRecorder = $options->getMetricsRecorder();

        if (!$options->isMonitorEnabled()) {
            return $userRecorder;
        }

        $inMemory = $container->get(InMemoryMetricsRecorder::class);

        if ($userRecorder instanceof NullMetricsRecorder) {
            return $inMemory;
        }

        return new MetricsRecorderChain(
            $inMemory,
            $userRecorder,
        );
    }

    /**
     * The snapshot source for cn=monitor: the live in-memory recorder under Swoole, or the parent-published file under
     * the forking PCNTL runner.
     */
    private function makeMetricsSnapshotProvider(Container $container): MetricsSnapshotProvider
    {
        $options = $container->get(ServerListenerOptionsInterface::class);

        if ($options->getRunner() !== RunnerMode::Swoole) {
            return new FileSnapshotProvider($options->getMonitorSnapshotPath());
        }

        return $container->get(InMemoryMetricsRecorder::class);
    }
}
