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
use FreeDSx\Ldap\Protocol\LdapMessageResponse;

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
     * @return \Generator
     */
    public function getMessages()
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
                yield LdapMessageResponse::fromAsn1($type);
            }
        }
    }

    /**
     * @return LdapMessageResponse
     */
    public function getMessage() : LdapMessageResponse
    {
        return $this->getMessages()->current();
    }
}
