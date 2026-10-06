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

use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles a CancelRequest (RFC 3909) whose target is not an operation still in progress.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerCancelHandler implements ServerProtocolHandlerInterface
{
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        $resultCode = $this->namesItself($message)
            ? ResultCode::CANNOT_CANCEL
            : ResultCode::NO_SUCH_OPERATION;

        return ResponseStream::reply(
            $message,
            OperationOutcomeResult::failed($resultCode),
            new ExtendedResponse(new LdapResult($resultCode)),
        );
    }

    /**
     * RFC 3909 §3: a Cancel is not cancelable, so one naming itself is the only outstanding target it can see.
     */
    private function namesItself(LdapMessageRequest $message): bool
    {
        $request = $message->getRequest();

        return $request instanceof CancelRequest
            && $request->getMessageId() === $message->getMessageId();
    }
}
