<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;

/**
 * Logic for handling a StartTLS operation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientStartTlsHandler implements ResponseHandlerInterface
{
    /**
     * {@inheritDoc}
     */
    public function handleResponse(LdapMessageRequest $messageTo, LdapMessageResponse $messageFrom, ClientQueue $queue, array $options): ?LdapMessageResponse
    {
        /** @var ExtendedResponse $response */
        $response = $messageFrom->getResponse();

        if ($response->getResultCode() !== ResultCode::SUCCESS) {
            throw new ConnectionException(sprintf(
                'Unable to start TLS: %s',
                $response->getDiagnosticMessage()
            ));
        }
        $queue->encrypt();

        return $messageFrom;
    }
}
