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

namespace FreeDSx\Ldap\Server\Metrics\Rollup;

use FreeDSx\Ldap\Server\Metrics\Snapshot\OperationMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\TrafficMetrics;
use FreeDSx\Ldap\Server\Process\Channel\ChannelMessage;
use FreeDSx\Ldap\Server\Process\Channel\ChannelMessageFactory;

use function is_array;

/**
 * Rebuilds a MetricsDeltaMessage from its wire form on the parent's end of a ChildChannel.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class MetricsDeltaMessageFactory implements ChannelMessageFactory
{
    /**
     * @param array<array-key, mixed> $data
     */
    public function fromArray(array $data): ChannelMessage
    {
        $operations = $data['operations'] ?? null;
        $traffic = $data['traffic'] ?? null;

        return new MetricsDeltaMessage(new MetricsDelta(
            OperationMetrics::fromArray(is_array($operations) ? $operations : []),
            TrafficMetrics::fromArray(is_array($traffic) ? $traffic : []),
        ));
    }
}
