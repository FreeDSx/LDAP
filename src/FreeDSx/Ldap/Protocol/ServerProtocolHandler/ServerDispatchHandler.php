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
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles generic requests that can be sent to the user supplied dispatcher / handler.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerDispatchHandler extends BaseServerHandler implements ServerProtocolHandlerInterface
{
    public function __construct(
        private readonly ServerQueue $queue,
        private readonly RequestHandlerInterface $dispatcher,
    ) {
        parent::__construct();
    }

    /**
     * {@inheritDoc}
     * @throws OperationException
     * @throws EncoderException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token
    ): void {
        $context = new RequestContext($message->controls(), $token);
        $request = $message->getRequest();

        if ($request instanceof Request\AddRequest) {
            $this->dispatcher->add($context, $request);
        } elseif ($request instanceof Request\CompareRequest) {
            $this->dispatcher->compare($context, $request);
        } elseif ($request instanceof Request\DeleteRequest) {
            $this->dispatcher->delete($context, $request);
        } elseif ($request instanceof Request\ModifyDnRequest) {
            $this->dispatcher->modifyDn($context, $request);
        } elseif ($request instanceof Request\ModifyRequest) {
            $this->dispatcher->modify($context, $request);
        } elseif ($request instanceof Request\ExtendedRequest) {
            $this->dispatcher->extended($context, $request);
        } else {
            throw new OperationException(
                'The requested operation is not supported.',
                ResultCode::NO_SUCH_OPERATION
            );
        }

        $this->queue->sendMessage($this->responseFactory->getStandardResponse($message));
    }
}
