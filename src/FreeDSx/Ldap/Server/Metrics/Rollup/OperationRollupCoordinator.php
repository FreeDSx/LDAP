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

use FreeDSx\Ldap\Server\Process\ChannelMessageFactory;
use FreeDSx\Ldap\Server\Process\ChildChannel;

/**
 * Moves child operation metrics to the parent over a ChildChannel.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class OperationRollupCoordinator
{
    /**
     * Batch sends by op count and elapsed time to keep the frame rate low.
     */
    private const FLUSH_OPS = 256;

    private const FLUSH_INTERVAL_SECONDS = 0.1;

    /**
     * How long an exiting child waits for a stalled parent to take its last frames.
     */
    private const FINISH_TIMEOUT_SECONDS = 1.0;

    private ?ChildChannel $boundChannel = null;

    private int $opsSinceSend = 0;

    private float $lastSendAt = 0.0;

    public function __construct(
        private readonly MetricsRollupInterface $recorder,
        private readonly ChannelMessageFactory $messageFactory = new MetricsDeltaMessageFactory(),
    ) {}

    public function openChannel(): ChildChannel
    {
        return ChildChannel::create($this->messageFactory);
    }

    /**
     * In the child: clear metrics inherited from the parent and bind the channel this child reports on.
     */
    public function enterChild(ChildChannel $channel): void
    {
        $this->recorder->resetDelta();
        $this->boundChannel = $channel;
        $this->opsSinceSend = 0;
        $this->lastSendAt = microtime(true);
    }

    /**
     * In the child: report accumulated metrics once the batch reaches its op count or time bound.
     */
    public function flush(): void
    {
        $this->opsSinceSend++;

        if ($this->batchIsReady()) {
            $this->sendDelta();
        }
    }

    /**
     * In the child: send the final accumulated delta, then close the write end so the parent reads EOF.
     */
    public function finish(): void
    {
        if ($this->boundChannel === null) {
            return;
        }

        $this->boundChannel->send(new MetricsDeltaMessage($this->recorder->takeDelta()));
        $this->boundChannel->drain(self::FINISH_TIMEOUT_SECONDS);
        $this->boundChannel->closeWrite();
    }

    /**
     * In the parent: fold any metrics deltas available on a child's channel into the totals.
     */
    public function collect(ChildChannel $channel): void
    {
        foreach ($channel->receive() as $message) {
            if ($message instanceof MetricsDeltaMessage) {
                $this->recorder->mergeDelta($message->delta());
            }
        }
    }

    /**
     * Whether the accumulated batch has reached its op-count or time bound and should be sent.
     */
    private function batchIsReady(): bool
    {
        return $this->opsSinceSend >= self::FLUSH_OPS
            || (microtime(true) - $this->lastSendAt) >= self::FLUSH_INTERVAL_SECONDS;
    }

    private function sendDelta(): void
    {
        if ($this->boundChannel === null || !$this->boundChannel->flush()) {
            return;
        }

        $this->boundChannel->send(new MetricsDeltaMessage($this->recorder->takeDelta()));
        $this->opsSinceSend = 0;
        $this->lastSendAt = microtime(true);
    }
}
