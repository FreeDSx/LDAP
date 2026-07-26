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
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\ProxyServerOptions;
use FreeDSx\Ldap\Server\Process\BackgroundTask\BackgroundTasksInterface;
use FreeDSx\Ldap\Server\Process\BackgroundTask\PcntlBackgroundTasks;
use FreeDSx\Ldap\Server\Process\BackgroundTask\SwooleBackgroundTasks;
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
            ServerProtocolFactoryInterface::class => static fn(Container $c): ServerProtocolFactoryInterface => new ProxyProtocolFactory($c->get(ProxyOptions::class)),
            BackgroundTasksInterface::class => $this->makeBackgroundTasks(...),
            ListenerContributorInterface::class => static fn(): ListenerContributorInterface => new ProxyListenerContributor(),
        ];
    }

    private function makeBackgroundTasks(Container $container): BackgroundTasksInterface
    {
        $options = $container->get(ProxyServerOptions::class);

        if ($options->isRunnerMode(RunnerMode::Swoole)) {
            return new SwooleBackgroundTasks(
                [],
                [],
                $options->getLogger(),
            );
        }

        return new PcntlBackgroundTasks(
            periodicTasks: [],
            longLivedTasks: [],
            logger: $options->getLogger(),
            gracefulStopSeconds: $options->getNetworkConfig()->getShutdownTimeout(),
        );
    }
}
