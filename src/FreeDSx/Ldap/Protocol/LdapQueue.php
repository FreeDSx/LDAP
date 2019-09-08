<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Encoder\EncoderInterface;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Socket\Queue\Asn1MessageQueue;
use FreeDSx\Socket\Queue\Message;
use FreeDSx\Socket\Exception\ConnectionException;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketPool;

/**
 * The LDAP Queue class for sending and receiving messages.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapQueue extends Asn1MessageQueue
{
    /**
     * @var int
     */
    protected const BUFFER_SIZE = 8192;

    /**
     * @var int
     */
    protected $id = 0;

    /**
     * @var bool
     */
    protected $serverMode;

    /**
     * @var SocketPool
     */
    protected $socketPool;

    public function __construct(Socket $socket, bool $serverMode = false, EncoderInterface $encoder = null)
    {
        $this->serverMode = $serverMode;
        parent::__construct($socket,$encoder ?? new LdapEncoder());
    }

    /**
     * Instantiate using a socket pool. This allows the queue to be reset / closed and then reconnect based on different
     * operations that are happening.
     *
     * @throws ConnectionException
     */
    public static function usingSocketPool(SocketPool $socketPool, bool $serverMode = false, EncoderInterface $encoder = null) : self
    {
        $queue = new self($socketPool->connect(), $serverMode,  $encoder);
        $queue->socketPool = $socketPool;

        return $queue;
    }

    /**
     * Encrypt messages sent by the socket for the queue.
     *
     * @return $this
     * @throws ConnectionException
     */
    public function encrypt()
    {
        $this->initSocket();
        $this->socket->block(true);
        $this->socket->encrypt(true);
        $this->socket->block(false);

        return $this;
    }

    /**
     * @return bool
     */
    public function isEncrypted(): bool
    {
        return $this->socket && $this->socket->isEncrypted();
    }
    /**
     * Cleanly close the socket and clear buffer contents.
     */
    public function close()
    {
        if ($this->socket !== null) {
            $this->socket->close();
        }
        $this->socket = null;
        $this->buffer = false;
        $this->id = 0;
    }

    /**
     * Generates a message ID to be sent out the queue.
     */
    public function generateId() : int
    {
        return ++$this->id;
    }

    /**
     * Get the current ID that the queue is on.
     */
    public function currentId() : int
    {
        return $this->id;
    }

    /**
     * Send LDAP messages out the socket.
     *
     * The logic in the loop is to send the messages in chunks of 8192 bytes to lessen the amount of TCP writes we need
     * to perform if sending out many messages.
     */
    public function sendMessage(LdapMessage ...$messages) : self
    {
        $this->initSocket();

        $buffer = '';
        foreach ($messages as $message) {
            $buffer .= $this->encoder->encode($message->toAsn1());
            $bufferLen = \strlen($buffer);
            if ($bufferLen >= self::BUFFER_SIZE) {
                $this->socket->write(\substr($buffer, 0, self::BUFFER_SIZE));
                $buffer = $bufferLen > self::BUFFER_SIZE ? \substr($buffer, self::BUFFER_SIZE) : '';
            }
        }
        if (\strlen($buffer)) {
            $this->socket->write($buffer);
        }

        return $this;
    }

    /**
     * @throws UnsolicitedNotificationException
     * @throws ConnectionException
     * @throws EncoderException
     * @return LdapMessageResponse|LdapMessageRequest
     */
    public function getMessage(?int $id = null) : LdapMessage
    {
        /** @var LdapMessage $message */
        $this->initSocket();
        $message = parent::getMessage($id);

        /**
         * This logic exists in the queue because an unsolicited notification can be received at any time. So we cannot
         * rely on logic in the handler determined for the initial request / response.
         */
        if ($message->getMessageId() === 0 && $message instanceof LdapMessageResponse && $message->getResponse() instanceof ExtendedResponse) {
            /** @var ExtendedResponse $response */
            $response = $message->getResponse();
            throw new UnsolicitedNotificationException(
                $response->getDiagnosticMessage(),
                $response->getResultCode(),
                null,
                (string) $response->getName()
            );
        }
        if ($id !== null && $message->getMessageId() !== $id) {
            throw new ProtocolException(sprintf(
                'Expected message ID %s, but received %s',
                $id,
                $message->getMessageId()
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

    /**
     * @return bool
     */
    public function isConnected() : bool
    {
        return $this->socket !== null && $this->socket->isConnected();
    }

    /**
     * {@inheritDoc}
     */
    protected function constructMessage(Message $message, ?int $id = null)
    {
        if ($this->serverMode) {
            return LdapMessageRequest::fromAsn1($message->getMessage());
        } else {
            return LdapMessageResponse::fromAsn1($message->getMessage());
        }
    }

    /**
     * @throws ConnectionException
     */
    protected function initSocket() : void
    {
        if ($this->socketPool && $this->socket === null) {
            $this->socket = $this->socketPool->connect();
        }
        if ($this->socketPool === null && $this->socket === null) {
            throw new ConnectionException('Unable to re-initialize a closed socket.');
        }
    }
}
