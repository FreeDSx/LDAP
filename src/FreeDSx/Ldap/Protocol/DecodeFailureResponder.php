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
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;

/**
 * Answers a message whose envelope parsed but whose body did not.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class DecodeFailureResponder
{
    public function __construct(
        private ServerQueue $queue,
        private EventLogger $eventLogger = new EventLogger(null),
        private ResponseFactory $responseFactory = new ResponseFactory(),
    ) {}

    /**
     * @throws EncoderException
     */
    public function answer(MessageDecodeException $e): bool
    {
        $response = $this->responseFactory->getDecodeFailureResponse(
            $e->getMessageId(),
            $e->getProtocolOpTag(),
            $e->getMessage(),
            $e->getResultCode(),
        );

        // An operation with no response, or a response tag masquerading as a request, leaves nothing to answer with.
        if ($response === null) {
            return false;
        }

        $this->eventLogger->record(
            ServerEvent::MessageDecodeFailed,
            [
                EventContext::REASON_MESSAGE => $e->getMessage(),
                EventContext::REASON_CODE => $e->getResultCode(),
            ],
        );
        $this->queue->sendMessage($response);

        return true;
    }
}
