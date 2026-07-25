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

namespace FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Protocol\Bind\AnonymousBind;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseInterceptor;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\ServerListenerOptionsInterface;
use FreeDSx\Socket\Socket;

/**
 * Shared per-connection construction used by the directory and proxy protocol factories.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait ServerConnectionScaffoldingTrait
{
    abstract protected function serverOptions(): ServerListenerOptionsInterface;

    /**
     * @param ResponseInterceptor[] $interceptors applied to every outgoing response, in order.
     */
    private function makeServerQueue(
        Socket $socket,
        array $interceptors = [],
        MetricsRecorderInterface $metricsRecorder = new NullMetricsRecorder(),
    ): ServerQueue {
        return new ServerQueue(
            $socket,
            maxReceiveSize: $this->serverOptions()->getNetworkConfig()->getMaxRequestSize(),
            interceptors: $interceptors,
            metricsRecorder: $metricsRecorder,
        );
    }

    private function makeEventLogger(ConnectionContext $context): EventLogger
    {
        return new EventLogger(
            $this->serverOptions()->getLogger(),
            $this->serverOptions()->getEventLogPolicy(),
            $context->toLogContext(),
        );
    }

    private function makeAnonymousBind(
        ServerQueue $queue,
        EventLogger $eventLogger,
    ): AnonymousBind {
        return new AnonymousBind(
            $queue,
            $eventLogger,
        );
    }
}
