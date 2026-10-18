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

namespace FreeDSx\Ldap\Protocol\Queue;

use FreeDSx\Asn1\Encoder\EncoderInterface;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Helper\AttributeEntryDecoder;
use FreeDSx\Asn1\Helper\AttributeEntryMessage;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessage;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\LdapQueue;
use FreeDSx\Socket\Exception\ConnectionException;
use FreeDSx\Socket\Exception\PartialMessageException;
use FreeDSx\Socket\Queue\Message;
use FreeDSx\Socket\SocketPool;

/**
 * The LDAP Queue class for sending and receiving messages for clients.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientQueue extends LdapQueue
{
    private bool $shouldReconnect = false;

    /**
     * @throws ConnectionException
     */
    public function __construct(
        private readonly SocketPool $socketPool,
        ?EncoderInterface $encoder = null,
        private readonly AttributeEntryDecoder $entryDecoder = new AttributeEntryDecoder(),
    ) {
        parent::__construct(
            $socketPool->connect(),
            $encoder,
        );
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
                get_class($message),
            ));
        }

        return $message;
    }

    /**
     * @throws ConnectionException
     * @throws EncoderException
     */
    public function sendMessage(LdapMessageRequest ...$messages): self
    {
        $this->initSocket();
        $this->sendLdapMessage($messages);

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
     * Decodes search result entries directly from BER, and anything else through the ASN.1 type graph.
     *
     * @throws PartialMessageException
     * @throws ProtocolException
     */
    protected function decode(string $bytes): Message
    {
        try {
            $entry = $this->entryDecoder->decode(
                $bytes,
                SearchResultEntry::TAG_NUMBER,
            );
        } catch (PartialPduException $e) {
            throw new PartialMessageException(
                $e->getMessage(),
                $e->getCode(),
                $e,
            );
        } catch (EncoderException) {
            # A malformed entry is decoded through the type graph, so it fails or is tolerated as any other message is.
            return parent::decode($bytes);
        }

        if ($entry === null || $this->isEntryMessageIdInvalid($entry)) {
            return parent::decode($bytes);
        }

        $message = new Message(
            new LdapMessageResponse(
                $entry->messageId,
                SearchResultEntry::fromAttributeEntry($entry),
            ),
            $entry->length,
        );
        $this->onMessageDecoded($message);

        return $message;
    }

    /**
     * {@inheritDoc}
     * @throws ProtocolException
     * @throws EncoderException
     * @throws PartialPduException
     * @throws RuntimeException
     */
    protected function constructMessage(
        Message $message,
        ?int $id = null,
    ): LdapMessageResponse {
        $type = $message->getMessage();

        if ($type instanceof LdapMessageResponse) {
            return $type;
        }
        if (!$type instanceof AbstractType) {
            throw new ProtocolException('The message received is invalid.');
        }

        return LdapMessageResponse::fromAsn1($type);
    }

    /**
     * @throws ConnectionException
     */
    private function initSocket(): void
    {
        if ($this->shouldReconnect) {
            $this->socket = $this->socketPool->connect();
            $this->shouldReconnect = false;
        }
    }

    private function isEntryMessageIdInvalid(AttributeEntryMessage $entry): bool
    {
        return $entry->messageId < 0
            || $entry->messageId > LdapMessage::MAX_INT;
    }
}
