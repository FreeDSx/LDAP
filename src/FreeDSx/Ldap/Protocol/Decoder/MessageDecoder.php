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

namespace FreeDSx\Ldap\Protocol\Decoder;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\ControlDecoderInterface;
use FreeDSx\Ldap\Protocol\LdapMessage;
use FreeDSx\Ldap\Protocol\ProtocolElementInterface;

/**
 * Decodes each received message into the operation it carries and its controls, for the side that receives it.
 *
 * @template TOperation of ProtocolElementInterface
 * @template TMessage of LdapMessage
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
abstract readonly class MessageDecoder
{
    /**
     * @param array<int, OperationDecoderInterface<TOperation>> $operations keyed by protocolOp tag.
     */
    public function __construct(
        private MessageEnvelopeReader $envelopes,
        private DecodeContextFactory $contexts,
        private array $operations,
        private ControlDecoderInterface $controls,
    ) {}

    /**
     * @param AbstractType<mixed> $pdu
     * @return TMessage
     * @throws ProtocolException when the envelope cannot be read, which ends the session.
     * @throws MessageDecodeException when anything past the envelope fails, which names the message ID.
     */
    public function decode(AbstractType $pdu): LdapMessage
    {
        $envelope = $this->envelopes->read($pdu);
        // Resolved before anything is decoded, so an unrecognized operation ends the session (RFC 4511 4.1.1).
        $decoder = $this->operations[$envelope->operationTag]
            ?? throw $this->envelopes->unsupported($envelope->operationTag);
        $context = $this->contexts->create();

        [$operation, $controls] = $this->envelopes->answerable(
            $envelope,
            fn(): array => [
                $decoder->decode(
                    $envelope->operation,
                    $context,
                ),
                $this->envelopes->controlsOf(
                    $envelope,
                    $context,
                    $this->controls,
                ),
            ],
        );

        return $this->message(
            $envelope->messageId,
            $operation,
            ...$controls,
        );
    }

    /**
     * Wraps the decoded operation and its controls in the message this side receives.
     *
     * @param TOperation $operation
     * @return TMessage
     */
    abstract protected function message(
        int $messageId,
        ProtocolElementInterface $operation,
        Control ...$controls,
    ): LdapMessage;
}
