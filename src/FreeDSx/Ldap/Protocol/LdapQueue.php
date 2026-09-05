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

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Encoder\EncoderInterface;
use FreeDSx\Asn1\Encoder\EncoderOptions;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PduLengthException;
use FreeDSx\Asn1\Helper\AttributeEntryEncoder;
use FreeDSx\Asn1\Type\SequenceOfType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RequestSizeExceededException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\Queue\MessageWrapperInterface;
use FreeDSx\Socket\Exception\ConnectionException;
use FreeDSx\Socket\Queue\Asn1MessageQueue;
use FreeDSx\Socket\Queue\Buffer;
use FreeDSx\Socket\Queue\Message;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\Tls\Certificate;

use function strlen;
use function substr;

/**
 * The LDAP Queue class for sending and receiving messages.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapQueue extends Asn1MessageQueue
{
    private const BUFFER_SIZE = 8192;

    private int $id = 0;

    private ?MessageWrapperInterface $messageWrapper = null;

    private readonly AttributeEntryEncoder $entryEncoder;

    public function __construct(
        Socket $socket,
        ?EncoderInterface $encoder = null,
        int $maxReceiveSize = 0,
    ) {
        parent::__construct(
            $socket,
            $encoder ?? new LdapEncoder(new EncoderOptions(maxLength: $maxReceiveSize)),
        );
        $this->entryEncoder = new AttributeEntryEncoder();
    }

    /**
     * Encrypt messages sent by the socket for the queue.
     *
     * @throws ConnectionException
     */
    public function encrypt(): static
    {
        // Anything read ahead arrived in the clear and should be dropped.
        $this->buffer = '';
        $this->toConsume = '';

        $this->socket->block(true);
        $this->socket->encrypt(true);
        $this->socket->block(false);

        return $this;
    }

    public function hasBufferedInput(): bool
    {
        return $this->hasBuffer();
    }

    public function isEncrypted(): bool
    {
        return ($this->socket->isConnected() && $this->socket->isEncrypted());
    }

    public function peerCertificate(): ?Certificate
    {
        return $this->socket->getPeerCertificate();
    }

    /**
     * Cleanly close the socket and clear buffer contents.
     */
    public function close(): void
    {
        $this->socket->close();
        $this->buffer = '';
        $this->toConsume = '';
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

    public function setMessageWrapper(?MessageWrapperInterface $messageWrapper): static
    {
        $this->messageWrapper = $messageWrapper;

        return $this;
    }

    public function isConnected(): bool
    {
        return $this->socket->isConnected();
    }

    /**
     * {@inheritDoc}
     */
    protected function unwrap(string $bytes): Buffer
    {
        if ($this->messageWrapper === null) {
            return parent::unwrap($bytes);
        }

        return $this->messageWrapper->unwrap($bytes);
    }

    /**
     * {@inheritDoc}
     *
     * @throws RequestSizeExceededException
     */
    protected function decode(string $bytes): Message
    {
        try {
            $message = parent::decode($bytes);
        } catch (PduLengthException $e) {
            throw new RequestSizeExceededException(
                $e->getMessage(),
                previous: $e,
            );
        }
        $this->onMessageDecoded($message);

        return $message;
    }

    /**
     * Send LDAP messages out the socket.
     *
     * Accepts any iterable (array, generator, …) so streaming producers can feed messages without
     * materializing them up front. Messages are encoded and appended to an 8KB buffer; the buffer
     * flushes whenever it fills, keeping syscall count low on large result sets.
     *
     * @param iterable<LdapMessage> $messages
     * @throws EncoderException
     */
    protected function sendLdapMessage(iterable $messages): static
    {
        $buffer = '';

        foreach ($messages as $message) {
            $encoded = $this->encodeMessage($message);
            $this->onMessageEncoded($encoded);
            $buffer .= $this->wrapEncoded($encoded);
            $buffer = $this->flushFilledChunks($buffer);
        }

        if (strlen($buffer) > 0) {
            $this->socket->write($buffer);
        }

        return $this;
    }

    /**
     * Extension point invoked with each message's encoded bytes as it is sent.
     */
    protected function onMessageEncoded(string $encoded): void {}

    /**
     * Extension point invoked with each message decoded off the socket.
     */
    protected function onMessageDecoded(Message $message): void {}

    /**
     * True if data is already buffered or available on the socket without blocking.
     */
    protected function hasPendingData(): bool
    {
        if ($this->hasBuffer()) {
            return true;
        }

        $data = $this->socket->read(false);
        if ($data === false || $data === '') {
            return false;
        }

        $this->buffer .= $data;

        return true;
    }

    /**
     * @throws ConnectionException
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     */
    protected function getAndValidateMessage(?int $id): LdapMessage
    {
        $message = parent::getMessage($id);

        if (!$message instanceof LdapMessage) {
            throw new ProtocolException(sprintf(
                'Expected instance of LdapMessage, received %s',
                is_object($message) ? $message::class : gettype($message),
            ));
        }

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
                (string) $response->getName(),
            );
        }
        if ($id !== null && $message->getMessageId() !== $id) {
            throw new ProtocolException(sprintf(
                'Expected message ID %s, but received %s',
                $id,
                $message->getMessageId(),
            ));
        }

        return  $message;
    }

    private function wrapEncoded(string $encoded): string
    {
        return $this->messageWrapper !== null
            ? $this->messageWrapper->wrap($encoded)
            : $encoded;
    }

    private function flushFilledChunks(string $buffer): string
    {
        while (strlen($buffer) >= self::BUFFER_SIZE) {
            $this->socket->write(substr($buffer, 0, self::BUFFER_SIZE));
            $buffer = substr($buffer, self::BUFFER_SIZE);
        }

        return $buffer;
    }

    /**
     * Encodes a message to BER, taking a dedicated fast path for search result entries.
     *
     * @throws ProtocolException
     */
    private function encodeMessage(LdapMessage $message): string
    {
        try {
            return $this->encodeMessageBody($message);
        } catch (EncoderException $e) {
            throw new ProtocolException(
                'The response could not be encoded.',
                previous: $e,
            );
        }
    }

    /**
     * @throws EncoderException
     */
    private function encodeMessageBody(LdapMessage $message): string
    {
        $response = $message instanceof LdapMessageResponse
            ? $message->getResponse()
            : null;

        if (!($response instanceof SearchResultEntry)) {
            return $this->encoder->encode($message->toAsn1());
        }

        $envelope = Asn1::sequence(
            Asn1::integer($message->getMessageId()),
            Asn1::raw($this->encodeSearchResultEntry($response)),
        );

        $controls = $message->controls()->toArray();
        if ($controls !== []) {
            /** @var SequenceOfType $context */
            $context = Asn1::context(
                tagNumber: 0,
                type: Asn1::sequenceOf(),
            );
            foreach ($controls as $control) {
                $context->addChild($control->toAsn1());
            }
            $envelope->addChild($context);
        }

        return $this->encoder->encode($envelope);
    }

    /**
     * @throws EncoderException
     */
    private function encodeSearchResultEntry(SearchResultEntry $response): string
    {
        $entry = $response->getEntry();
        $attributes = [];
        foreach ($entry->getAttributes() as $attribute) {
            $attributes[] = [
                $attribute->getDescription(),
                $attribute->getValues(),
            ];
        }

        return $this->entryEncoder->encode(
            SearchResultEntry::TAG_NUMBER,
            $entry->getDn()->toString(),
            $attributes,
        );
    }
}
