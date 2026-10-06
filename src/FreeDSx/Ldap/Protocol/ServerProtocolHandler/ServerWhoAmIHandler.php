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
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles a whoami request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerWhoAmIHandler implements ServerProtocolHandlerInterface
{
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        // RFC 4532 §3: an anonymous identity gets a response field that is present but empty.
        $userId = '';

        if ($token instanceof AuthenticatedTokenInterface) {
            $userId = $token->getAuthzId()->toString();
        }

        return ResponseStream::reply(
            $message,
            OperationOutcomeResult::succeeded(),
            new ExtendedResponse(
                new LdapResult(ResultCode::SUCCESS),
                null,
                $userId,
            ),
        );
    }
}
