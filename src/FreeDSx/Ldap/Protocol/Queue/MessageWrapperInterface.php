<?php

namespace FreeDSx\Ldap\Protocol\Queue;

use FreeDSx\Socket\Queue\Message;

/**
 * Used to wrap / unwrap messages after ASN.1 encoding, or prior to ASN.1 decoding.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface MessageWrapperInterface
{
    /**
     * Wrap the message after it is encode to ASN.1.
     *
     * @param string $message
     * @return string
     */
    public function wrap(string $message): string;

    /**
     * Unwrap the message before it is decoded to ASN.1.
     *
     * @param string $message
     * @return string
     */
    public function unwrap(string $message): string;

    /**
     * Any final adjustments needed after the unwrap process decoding ASN.1 (moving the last position...).
     *
     * @param Message $message
     * @return Message
     */
    public function postUnwrap(Message $message): Message;
}
