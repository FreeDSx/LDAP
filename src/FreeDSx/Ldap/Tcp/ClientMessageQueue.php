<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Tcp;

use FreeDSx\Ldap\Asn1\Encoder\EncoderInterface;
use FreeDSx\Ldap\Exception\PartialPduException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;

/**
 * Used to retrieve message envelopes from the TCP stream.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientMessageQueue
{
    /**
     * @var TcpClient
     */
    protected $tcp;

    /**
     * @var EncoderInterface
     */
    protected $encoder;

    /**
     * @var false|string
     */
    protected $buffer = false;

    /**
     * @param TcpClient $tcp
     * @param EncoderInterface $encoder
     */
    public function __construct(TcpClient $tcp, EncoderInterface $encoder)
    {
        $this->tcp = $tcp;
        $this->encoder = $encoder;
    }

    /**
     * @param int|null $id
     * @return \Generator
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     */
    public function getMessages(?int $id = null)
    {
        $this->buffer = ($this->buffer !== false) ? $this->buffer : $this->tcp->read();

        while ($this->buffer !== false) {
            $type = null;
            try {
                /** @var LdapMessageResponse $response */
                $type = $this->encoder->decode($this->buffer);
                $this->buffer = false;

                if ($type->getTrailingData() != '') {
                    $this->buffer = $type->getTrailingData();
                } elseif (($peek = $this->tcp->read(false)) !== false) {
                    $this->buffer .= $peek;
                }
            } catch (PartialPduException $e) {
                $this->buffer .= $this->tcp->read();
            }

            if ($type !== null) {
                yield $this->validate(LdapMessageResponse::fromAsn1($type), $id);
            }
        }
    }

    /**
     * @param int|null $id
     * @return LdapMessageResponse
     */
    public function getMessage(?int $id = null) : LdapMessageResponse
    {
        return $this->getMessages($id)->current();
    }

    /**
     * Checks for two separate things:
     *
     *  - Unsolicited notification messages, which is a message with an ID of zero and an ExtendedResponse type.
     *  - Unexpected message ID responses if we expect a specific message ID to be returned.
     *
     * @param LdapMessageResponse $message
     * @param int|null $id
     * @return LdapMessageResponse
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     */
    protected function validate(LdapMessageResponse $message, ?int $id) : LdapMessageResponse
    {
        if ($message->getMessageId() === 0 && $message->getResponse() instanceof ExtendedResponse) {
            /** @var ExtendedResponse $response */
            $response = $message->getResponse();
            throw new UnsolicitedNotificationException(
                $response->getDiagnosticMessage(),
                $response->getResultCode(),
                null,
                $response->getName()
            );
        }
        if ($id !== null && $id !== $message->getMessageId()) {
            throw new ProtocolException(sprintf(
                'Expected a LDAP PDU with an ID %s, but received %s.',
                $id,
                $message->getMessageId()
            ));
        }

        return $message;
    }
}
