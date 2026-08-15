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

namespace FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Socket\Exception\ConnectionException;

/**
 * Logic for handling an abandon operation, which RFC 4511 §4.11 defines no response for.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientAbandonHandler implements RequestHandlerInterface
{
    use MessageCreationTrait;

    public function __construct(private readonly ClientQueue $queue) {}

    /**
     * {@inheritDoc}
     * @throws EncoderException
     * @throws ConnectionException
     */
    public function handleRequest(LdapMessageRequest $message): ?LdapMessageResponse
    {
        // Waiting for a reply would block until the read timeout, since a conformant server sends nothing.
        $this->queue->sendMessage($message);

        return null;
    }
}
