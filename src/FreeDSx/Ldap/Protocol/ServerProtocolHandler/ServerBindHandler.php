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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles a simple bind request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerBindHandler extends BaseServerHandler implements BindHandlerInterface
{
    public function __construct(private readonly ServerQueue $queue)
    {
        parent::__construct();
    }

    /**
     * {@inheritDoc}
     * @throws RuntimeException
     * @throws OperationException
     */
    public function handleBind(
        LdapMessageRequest $message,
        RequestHandlerInterface $dispatcher,
        ServerQueue $queue
    ): TokenInterface {
        /** @var BindRequest $request */
        $request = $message->getRequest();
        if (!$request instanceof SimpleBindRequest) {
            throw new RuntimeException(sprintf(
                'Expected a SimpleBindRequest, got: %s',
                get_class($request)
            ));
        }

        $this->validateVersion($request);
        $token = $this->simpleBind($dispatcher, $request);
        $this->queue->sendMessage($this->responseFactory->getStandardResponse($message));

        return $token;
    }

    /**
     * @throws OperationException
     */
    protected function validateVersion(BindRequest $request): void
    {
        # Per RFC 4.2, a result code of protocol error must be sent back for unsupported versions.
        if ($request->getVersion() !== 3) {
            throw new OperationException(
                'Only LDAP version 3 is supported.',
                ResultCode::PROTOCOL_ERROR
            );
        }
    }

    /**
     * @throws OperationException
     */
    private function simpleBind(
        RequestHandlerInterface $dispatcher,
        SimpleBindRequest $request
    ): TokenInterface {
        if (!$dispatcher->bind($request->getUsername(), $request->getPassword())) {
            throw new OperationException(
                'Invalid credentials.',
                ResultCode::INVALID_CREDENTIALS
            );
        }

        return new BindToken($request->getUsername(), $request->getPassword());
    }
}
