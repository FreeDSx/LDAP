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

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Replies to ExtendedRequests whose requestName the server does not recognize per RFC 4511 §4.12.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ServerUnsupportedExtendedHandler implements ServerProtocolHandlerInterface
{
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        $request = $message->getRequest();

        if (!$request instanceof ExtendedRequest) {
            throw new RuntimeException('The extended operation handler was routed a non-extended request.');
        }

        return ResponseStream::reply(
            $message,
            OperationOutcomeResult::failed(ResultCode::PROTOCOL_ERROR),
            // RFC 4511 4.12: the response names no OID when the request's own name was not recognized.
            new ExtendedResponse(
                new LdapResult(
                    ResultCode::PROTOCOL_ERROR,
                    '',
                    sprintf('The extended operation "%s" is not supported.', $request->getName()),
                ),
            ),
        );
    }
}
