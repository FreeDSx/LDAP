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

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\RequestValidationException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;

/**
 * Answers each request sent behind a persistent stream with operationsError.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class OutOfSequenceResponder
{
    private const OUT_OF_SEQUENCE = 'Another operation on this connection is still in progress.';

    public function __construct(
        private ServerQueue $queue,
        private EventLogger $eventLogger = new EventLogger(null),
        private ResponseFactory $responseFactory = new ResponseFactory(),
    ) {}

    /**
     * Drains every waiting request.
     *
     * @return ?LdapMessageRequest The Abandon, Cancel or Unbind that signals the stream.
     * @throws RequestValidationException If a request reuses the stream's message ID.
     * @throws MessageDecodeException If a request has an envelope that parses and a body that does not.
     * @throws EncoderException
     */
    public function signalOrRefuse(int $inFlightMessageId): ?LdapMessageRequest
    {
        while (($message = $this->queue->pollMessage()) !== null) {
            if ($this->consume($message, $inFlightMessageId)) {
                return $message;
            }
        }

        return null;
    }

    /**
     * Acts on one waiting request.
     *
     * @return bool Whether it signals the stream
     * @throws RequestValidationException
     * @throws EncoderException
     */
    private function consume(
        LdapMessageRequest $message,
        int $inFlightMessageId,
    ): bool {
        $request = $message->getRequest();

        // RFC 4511 4.1.1.1: the ID of an operation still in progress cannot be used again.
        if ($message->getMessageId() === $inFlightMessageId) {
            throw new RequestValidationException(sprintf(
                'The message ID %s is not valid.',
                $inFlightMessageId,
            ));
        }

        if (($request instanceof AbandonRequest || $request instanceof CancelRequest) && $request->getMessageId() === $inFlightMessageId) {
            return true;
        }

        // The dispatcher still ends the session the way an unbind normally does.
        if ($request instanceof UnbindRequest) {
            $this->queue->requeue($message);

            return true;
        }

        // An abandon has no response to refuse it with.
        if ($request instanceof AbandonRequest) {
            return false;
        }

        // A refused request is never processed.
        $this->refuse($message);

        return false;
    }

    /**
     * @throws EncoderException
     */
    private function refuse(LdapMessageRequest $message): void
    {
        $this->eventLogger->record(
            ServerEvent::OperationRefused,
            [
                EventContext::RESULT_CODE => ResultCode::OPERATIONS_ERROR,
                EventContext::REASON => self::OUT_OF_SEQUENCE,
            ],
            message: $message,
        );
        $this->queue->sendMessage($this->responseFactory->getStandardResponse(
            $message,
            ResultCode::OPERATIONS_ERROR,
            self::OUT_OF_SEQUENCE,
        ));
    }
}
