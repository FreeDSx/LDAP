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

use FreeDSx\Asn1\Encoder\EncoderInterface;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\LdapQueue;
use FreeDSx\Socket\Exception\ConnectionException;
use FreeDSx\Socket\Queue\Message;
use FreeDSx\Socket\SocketPool;

/**
 * The LDAP Queue class for sending and receiving messages for clients.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientQueue extends LdapQueue
{
    /**
     * @var bool
     */
    protected $shouldReconnect = false;

    /**
     * @var SocketPool
     */
    protected $socketPool;

    /**
     * @throws ConnectionException
     */
    public function __construct(SocketPool $socketPool, EncoderInterface $encoder = null)
    {
        $this->socketPool = $socketPool;
        parent::__construct($socketPool->connect(), $encoder);
    }

    /**
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     * @throws ConnectionException
     */
    public function getMessage(?int $id = null): LdapMessageResponse
    {
        $this->initSocket();

        $message = $this->getAndValidateMessage($id);
        if (!$message instanceof LdapMessageResponse) {
            throw new ProtocolException(sprintf(
                'Expected an instance of LdapMessageResponse but got: %s',
                get_class($message)
            ));
        }

        return $message;
    }

    /**
     * {@inheritDoc}
     */
    public function getMessages(?int $id = null)
    {
        $this->initSocket();

        return parent::getMessages($id);
    }

    public function sendMessage(LdapMessageRequest ...$messages): ClientQueue
    {
        $this->initSocket();
        $this->sendLdapMessage(...$messages);

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function close(): void
    {
        parent::close();
        $this->shouldReconnect = true;
    }

    /**
     * @throws ConnectionException
     */
    protected function initSocket(): void
    {
        if ($this->shouldReconnect) {
            $this->socket = $this->socketPool->connect();
            $this->shouldReconnect = false;
        }
    }

    /**
     * {@inheritDoc}
     */
    protected function constructMessage(Message $message, ?int $id = null)
    {
        return LdapMessageResponse::fromAsn1($message->getMessage());
    }
}
