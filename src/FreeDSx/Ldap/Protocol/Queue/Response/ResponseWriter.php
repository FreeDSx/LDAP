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

use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Protocol\DecodeFailureResponder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Operation\OperationResult;

use function count;

/**
 * Drains a handler's ResponseStream to the queue and resolves its outcome.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ResponseWriter
{
    public function __construct(
        private ServerQueue $queue,
        private DecodeFailureResponder $decodeFailures,
    ) {}

    public function write(
        ResponseStream $stream,
        int $messageId,
    ): OperationResult {
        if ($stream->writerConfig->mustFlushOrSignal()) {
            $this->step(
                $stream,
                $messageId,
            );
        } else {
            $this->queue->sendMessages($stream->messages);
        }

        // Post-write connection side effect (e.g. StartTLS encrypt) — the bytes are on the wire now.
        if ($stream->onComplete !== null) {
            ($stream->onComplete)($this->queue);
        }

        return $stream->outcome();
    }

    /**
     * Walk the generator, flushing in batches and offering polled cancel signals at the configured interval.
     */
    private function step(
        ResponseStream $stream,
        int $messageId,
    ): void {
        $config = $stream->writerConfig;
        // Flush per message for liveness, else batch up to the poll interval.
        $flushEvery = $config->flushPerMessage
            ? 1
            : max(1, $config->signalInterval);
        $chunk = [];
        $sincePoll = 0;

        // The producer reads the offered signal from the Cancellation token when foreach resumes it.
        foreach ($stream->generator() as $message) {
            $chunk[] = $message;
            $sincePoll++;

            if (count($chunk) >= $flushEvery) {
                $this->queue->sendMessages($chunk);
                $chunk = [];
            }

            if ($config->signalInterval > 0 && $sincePoll >= $config->signalInterval) {
                $sincePoll = 0;
                $stream->cancellation?->offer($this->pollForSignal($messageId));
            }
        }

        if ($chunk !== []) {
            $this->queue->sendMessages($chunk);
        }
    }

    /**
     * A message that arrives mid-stream is answered the same way one between operations is.
     *
     * @throws MessageDecodeException When the message cannot be answered at all.
     */
    private function pollForSignal(int $messageId): ?LdapMessageRequest
    {
        try {
            return $this->queue->peekForCancelSignal($messageId);
        } catch (MessageDecodeException $e) {
            if ($this->decodeFailures->answer($e)) {
                return null;
            }

            throw $e;
        }
    }
}
