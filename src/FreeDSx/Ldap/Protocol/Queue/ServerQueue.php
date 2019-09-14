<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\Queue;

use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\LdapQueue;
use FreeDSx\Socket\Queue\Message;

/**
 * The LDAP Queue class for sending and receiving messages for servers.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerQueue extends LdapQueue
{
    public function getMessage(?int $id = null): LdapMessageRequest
    {
        $message = $this->getAndValidateMessage($id);

        if (!$message instanceof LdapMessageRequest) {
            throw new ProtocolException(sprintf(
                'Expected an instance of LdapMessageResponse but got: %s',
                get_class($message)
            ));
        }

        return $message;
    }

    public function sendMessage(LdapMessageResponse ...$response): ServerQueue
    {
        $this->sendLdapMessage(...$response);

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    protected function constructMessage(Message $message, ?int $id = null)
    {
        return LdapMessageRequest::fromAsn1($message->getMessage());
    }
}
