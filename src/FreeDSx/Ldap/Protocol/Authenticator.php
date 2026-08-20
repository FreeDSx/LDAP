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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\SaslNegotiationAbortedException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Exception\ResponseAlreadySentException;
use FreeDSx\Ldap\Protocol\Bind\BindInterface;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Token\TokenInterface;

class Authenticator
{
    /**
     * @param BindInterface[] $authenticators
     */
    public function __construct(
        private readonly array $authenticators,
        private readonly ServerQueue $queue,
        private readonly ResponseFactory $responseFactory = new ResponseFactory(),
    ) {}

    /**
     * @throws OperationException
     * @throws ResponseAlreadySentException when a replacement bind was answered on its own message ID.
     */
    public function bind(LdapMessageRequest $request): TokenInterface
    {
        $dispatched = $request;

        while (true) {
            try {
                return $this->authenticate($dispatched);
            } catch (SaslNegotiationAbortedException $e) {
                // Each abort consumes a client message, so the bind that replaced it drives the next round.
                $dispatched = $e->request;
            } catch (OperationException $e) {
                if ($dispatched === $request) {
                    throw $e;
                }

                // The caller still holds the message this one replaced, so the refusal is answered here instead.
                throw $this->answer($dispatched, $e);
            }
        }
    }

    private function answer(
        LdapMessageRequest $message,
        OperationException $cause,
    ): ResponseAlreadySentException {
        $this->queue->sendMessage($this->responseFactory->getStandardResponse(
            $message,
            $cause->getCode(),
            $cause->getMessage(),
        ));

        return new ResponseAlreadySentException(
            $cause->getMessage(),
            $cause->getCode(),
            $cause,
        );
    }

    private function authenticate(LdapMessageRequest $request): TokenInterface
    {
        foreach ($this->authenticators as $authenticator) {
            if ($authenticator->supports($request)) {
                return $authenticator->bind($request);
            }
        }

        throw new OperationException(
            'The authentication type requested is not supported.',
            ResultCode::AUTH_METHOD_UNSUPPORTED,
        );
    }
}
