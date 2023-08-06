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

use Exception;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles a whoami request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerWhoAmIHandler implements ServerProtocolHandlerInterface
{
    public function __construct(private readonly ServerQueue $queue)
    {
    }

    /**
     * {@inheritDoc}
     * @throws EncoderException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
        RequestHandlerInterface $dispatcher
    ): void {
        $userId = $token->getUsername();

        if ($userId !== null) {
            try {
                (new Dn($userId))->toArray();
                $userId = 'dn:' . $userId;
            } catch (Exception) {
                $userId = 'u:' . $userId;
            }
        }

        $this->queue->sendMessage(new LdapMessageResponse(
            $message->getMessageId(),
            new ExtendedResponse(new LdapResult(ResultCode::SUCCESS), null, $userId)
        ));
    }
}
