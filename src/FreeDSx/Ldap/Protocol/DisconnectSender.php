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

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use Throwable;

/**
 * Sends the unsolicited notification that ends a client session (RFC 4511 §4.4.1).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class DisconnectSender
{
    public function __construct(
        private ServerQueue $queue,
        private EventLogger $eventLogger,
        private ResponseFactory $responseFactory = new ResponseFactory(),
    ) {}

    /**
     * @throws EncoderException
     */
    public function send(
        string $message = '',
        int $reasonCode = ResultCode::PROTOCOL_ERROR,
        ?Throwable $cause = null,
    ): void {
        $this->queue->sendMessage($this->responseFactory->getExtendedError(
            $message,
            $reasonCode,
            ExtendedResponse::OID_NOTICE_OF_DISCONNECTION,
        ));
        $this->eventLogger->record(
            ServerEvent::NoticeOfDisconnectSent,
            [
                EventContext::REASON_CODE => $reasonCode,
                EventContext::REASON_MESSAGE => $message,
            ] + $this->eventLogger->exceptionContextFor($cause),
        );
    }

    /**
     * For a failure that may itself have been the connection going away.
     *
     * @throws EncoderException
     */
    public function sendIfConnected(
        string $message = '',
        int $reasonCode = ResultCode::PROTOCOL_ERROR,
        ?Throwable $cause = null,
    ): void {
        if (!$this->queue->isConnected()) {
            return;
        }

        $this->send(
            $message,
            $reasonCode,
            $cause,
        );
    }
}
