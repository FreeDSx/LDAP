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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteCommandFactory;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles generic requests that are dispatched to the backend.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerDispatchHandler implements ServerProtocolHandlerInterface
{
    public function __construct(
        private readonly ServerQueue $queue,
        private readonly LdapBackendInterface $backend,
        private readonly WriteOperationDispatcher $writeDispatcher,
        private readonly WriteCommandFactory $commandFactory = new WriteCommandFactory(),
        private readonly ResponseFactory $responseFactory = new ResponseFactory(),
    ) {
    }

    /**
     * {@inheritDoc}
     *
     * @throws EncoderException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): void {
        try {
            $request = $message->getRequest();

            if ($request instanceof Request\CompareRequest) {
                $match = $this->backend->compare($request->getDn(), $request->getFilter());
                $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                    $message,
                    $match
                        ? ResultCode::COMPARE_TRUE
                        : ResultCode::COMPARE_FALSE,
                ));

                return;
            }

            $this->writeDispatcher->dispatch($this->commandFactory->fromRequest($request));

            $this->queue->sendMessage($this->responseFactory->getStandardResponse($message));
        } catch (OperationException $e) {
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $e->getCode(),
                $e->getMessage(),
            ));
        }
    }
}
