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

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Container\Contributor\ListenerContributorInterface;
use FreeDSx\Ldap\Container\Contributor\ProxyListenerContributor;
use FreeDSx\Ldap\Protocol\Decoder\RequestMessageDecoder;
use FreeDSx\Ldap\Protocol\Queue\Budget\RequestBudget;
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\ProxyServerOptions;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Initialization\Requirement\UpstreamConfidentialityRequirement;
use FreeDSx\Ldap\Server\Process\BackgroundTask\BackgroundTasksInterface;
use FreeDSx\Ldap\Server\Process\BackgroundTask\PcntlBackgroundTasks;
use FreeDSx\Ldap\Server\Process\BackgroundTask\SwooleBackgroundTasks;
use FreeDSx\Ldap\Server\Process\Child\ChildForker;
use FreeDSx\Ldap\Server\Proxy\ProxyProtocolFactory;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;

/**
 * Registers the forwarding-proxy services.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ProxyServerContainerProvider implements ContainerProviderInterface
{
    public function factories(): array
    {
        return [
            ServerProtocolFactoryInterface::class => $this->makeProtocolFactory(...),
            BackgroundTasksInterface::class => $this->makeBackgroundTasks(...),
            ListenerContributorInterface::class => $this->makeListenerContributor(...),
        ];
    }

    private function makeListenerContributor(Container $container): ListenerContributorInterface
    {
        return new ProxyListenerContributor([
            new UpstreamConfidentialityRequirement($container->get(ProxyOptions::class)),
        ]);
    }

    private function makeProtocolFactory(Container $container): ServerProtocolFactoryInterface
    {
        return new ProxyProtocolFactory(
            $container->get(ProxyOptions::class),
            $container->get(RequestMessageDecoder::class),
            $container->get(RequestBudget::class),
        );
    }

    private function makeBackgroundTasks(Container $container): BackgroundTasksInterface
    {
        $options = $container->get(ProxyServerOptions::class);
        $eventLogger = new EventLogger(
            $options->getLogger(),
            $options->getEventLogPolicy(),
        );

        if ($options->isRunnerMode(RunnerMode::Swoole)) {
            return new SwooleBackgroundTasks(
                [],
                [],
                $eventLogger,
            );
        }

        return new PcntlBackgroundTasks(
            childForker: $container->get(ChildForker::class),
            periodicTasks: [],
            longLivedTasks: [],
            eventLogger: $eventLogger,
            gracefulStopSeconds: $options->getNetworkConfig()->getShutdownTimeout(),
        );
    }
}
