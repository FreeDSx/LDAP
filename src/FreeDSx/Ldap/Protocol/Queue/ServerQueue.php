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
    /**
     * @param int|null $id
     * @return LdapMessageRequest
     * @throws ProtocolException
     * @throws \FreeDSx\Ldap\Exception\UnsolicitedNotificationException
     * @throws \FreeDSx\Socket\Exception\ConnectionException
     */
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

    /**
     * @param LdapMessageResponse ...$response
     * @return $this
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     */
    public function sendMessage(LdapMessageResponse ...$response): self
    {
        $this->sendLdapMessage(...$response);

        return $this;
    }

    /**
     * @param Message $message
     * @param int|null $id
     * @return LdapMessageRequest|mixed
     * @throws ProtocolException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     * @throws \FreeDSx\Asn1\Exception\PartialPduException
     * @throws \FreeDSx\Ldap\Exception\RuntimeException
     */
    protected function constructMessage(Message $message, ?int $id = null)
    {
        return LdapMessageRequest::fromAsn1($message->getMessage());
    }
}
