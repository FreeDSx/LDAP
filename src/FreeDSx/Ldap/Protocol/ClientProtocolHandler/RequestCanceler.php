<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use Closure;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;

class RequestCanceler
{
    private Closure $messageProcessor;

    /**
     * @phpstan-param 'stop'|'continue' $strategy
     */
    public function __construct(
        private readonly ClientQueue $queue,
        private readonly string $strategy = SearchRequest::CANCEL_STOP,
        ?Closure $messageProcessor = null,
    ) {
        $this->messageProcessor = $messageProcessor ?? fn () => null;
    }

    /**
     * @throws OperationException
     */
    public function cancel(int $idToCancel): ExtendedResponse
    {
        $cancelId = $this->queue->generateId();

        $this->queue->sendMessage(new LdapMessageRequest(
            $cancelId,
            Operations::cancel($idToCancel)
        ));

        do {
            $received = $this->queue->getMessage();

            if ($received->getMessageId() === $idToCancel && $this->strategy === SearchRequest::CANCEL_CONTINUE) {
                ($this->messageProcessor)($received);
            }
        } while ($received->getMessageId() !== $cancelId);

        /** @var ExtendedResponse $response */
        $response = $received->getResponse();
        $this->validateCancelation($received);

        return $response;
    }

    /**
     * @throws ProtocolException
     * @throws OperationException
     */
    private function validateCancelation(LdapMessageResponse $response): void
    {
        $result = $response->getResponse();

        if (!$result instanceof ExtendedResponse) {
            throw new ProtocolException(sprintf(
                'Expected an extended response from a cancel operation, but received: %s',
                get_class($result)
            ));
        }

        // This indicates the operation was canceled successfully. So there is nothing to do.
        if ($result->getResultCode() === ResultCode::CANCELED || $result->getResultCode() === ResultCode::SUCCESS) {
            return;
        }

        throw new OperationException(
            $result->getDiagnosticMessage(),
            $result->getResultCode()
        );
    }
}
