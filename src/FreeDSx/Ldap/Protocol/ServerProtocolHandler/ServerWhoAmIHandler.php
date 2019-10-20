<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

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
    /**
     * {@inheritDoc}
     */
    public function handleRequest(LdapMessageRequest $message, TokenInterface $token, RequestHandlerInterface $dispatcher, ServerQueue $queue, array $options): void
    {
        $userId = $token->getUsername();

        if ($userId !== null) {
            try {
                (new Dn($userId))->toArray();
                $userId = 'dn:' . $userId;
            } catch (\Exception $e) {
                $userId = 'u:' . $userId;
            }
        }

        $queue->sendMessage(new LdapMessageResponse(
            $message->getMessageId(),
            new ExtendedResponse(new LdapResult(ResultCode::SUCCESS), null, $userId)
        ));
    }
}
