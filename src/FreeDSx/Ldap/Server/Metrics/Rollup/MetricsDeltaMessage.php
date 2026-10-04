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

use FreeDSx\Ldap\Server\Process\Channel\ChannelMessage;

/**
 * Carries a child process's metrics delta to the parent over a ChildChannel.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class MetricsDeltaMessage implements ChannelMessage
{
    public function __construct(private MetricsDelta $delta) {}

    public function delta(): MetricsDelta
    {
        return $this->delta;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'operations' => $this->delta->operations->toArray(),
            'traffic' => $this->delta->traffic->toArray(),
        ];
    }
}
