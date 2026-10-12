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

namespace FreeDSx\Ldap\Protocol\Queue\Response;

/**
 * Tells the response writer how to drive a stream; defaults to the fully-batched, unpolled fast path.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class QueueWriterConfig
{
    /**
     * @param int $signalInterval poll for a cancel/abandon signal every N messages; 0 disables it.
     * @param bool $flushPerMessage flush the socket after each message instead of the default buffering.
     */
    public function __construct(
        public int $signalInterval = 0,
        public bool $flushPerMessage = false,
    ) {}

    public function mustFlushOrSignal(): bool
    {
        return $this->signalInterval > 0 || $this->flushPerMessage;
    }

    public function isPollDue(int $sinceLastPoll): bool
    {
        return $this->signalInterval > 0 && $sinceLastPoll >= $this->signalInterval;
    }
}
