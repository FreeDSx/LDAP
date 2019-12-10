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
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Protocol\Queue\MessageWrapperInterface;
use FreeDSx\Socket\Exception\ConnectionException;
use FreeDSx\Socket\Queue\Asn1MessageQueue;
use FreeDSx\Socket\Queue\Buffer;
use FreeDSx\Socket\Socket;

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
     * @var Socket
     */
    protected $socket;

    /**
     * @var MessageWrapperInterface|null
     */
    protected $messageWrapper;

    public function __construct(Socket $socket, EncoderInterface $encoder = null)
    {
        parent::__construct($socket, $encoder ?? new LdapEncoder());
    }

    /**
     * Encrypt messages sent by the socket for the queue.
     *
     * @return $this
     * @throws ConnectionException
     */
    public function encrypt()
    {
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
        return ($this->socket->isConnected() && $this->socket->isEncrypted());
    }

    /**
     * Cleanly close the socket and clear buffer contents.
     */
    public function close(): void
    {
        $this->socket->close();
        $this->buffer = false;
        $this->id = 0;
    }

    /**
     * Generates a message ID to be sent out the queue.
     */
    public function generateId(): int
    {
        return ++$this->id;
    }

    /**
     * Get the current ID that the queue is on.
     */
    public function currentId(): int
    {
        return $this->id;
    }

    /**
     * @param MessageWrapperInterface|null $messageWrapper
     * @return $this
     */
    public function setMessageWrapper(?MessageWrapperInterface $messageWrapper)
    {
        $this->messageWrapper = $messageWrapper;

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    protected function unwrap($bytes): Buffer
    {
        if ($this->messageWrapper === null) {
            return parent::unwrap($bytes);
        }

        return $this->messageWrapper->unwrap($bytes);
    }

    /**
     * Send LDAP messages out the socket.
     *
     * The logic in the loop is to send the messages in chunks of 8192 bytes to lessen the amount of TCP writes we need
     * to perform if sending out many messages.
     */
    protected function sendLdapMessage(LdapMessage ...$messages): self
    {
        $buffer = '';

        foreach ($messages as $message) {
            $encoded = $this->encoder->encode($message->toAsn1());
            $buffer .= $this->messageWrapper !== null ? $this->messageWrapper->wrap($encoded) : $encoded;
            $bufferLen = \strlen($buffer);
            if ($bufferLen >= self::BUFFER_SIZE) {
                $this->socket->write(\substr($buffer, 0, self::BUFFER_SIZE));
                $buffer = $bufferLen > self::BUFFER_SIZE ? \substr($buffer, self::BUFFER_SIZE) : '';
            }
        }
        if (\strlen($buffer) > 0) {
            $this->socket->write($buffer);
        }

        return $this;
    }

    /**
     * @return bool
     */
    public function isConnected(): bool
    {
        return $this->socket->isConnected();
    }

    /**
     * @throws ConnectionException
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     */
    protected function getAndValidateMessage(?int $id): LdapMessage
    {
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

        return  $message;
    }
}
