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
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\ControlDecoderInterface;
use FreeDSx\Ldap\Protocol\Decoder\Request\RequestDecoderInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;

/**
 * Decodes each message a client sends into the request it carries and its controls.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class RequestMessageDecoder
{
    /**
     * @param array<int, RequestDecoderInterface> $operations the decoder of each request, keyed by its protocolOp tag.
     */
    public function __construct(
        private MessageEnvelopeReader $envelopes,
        private DecodeContextFactory $contexts,
        private array $operations,
        private ControlDecoderInterface $controls,
    ) {}

    /**
     * @param AbstractType<mixed> $pdu
     * @throws ProtocolException when the envelope cannot be read, which ends the session.
     * @throws MessageDecodeException when anything past the envelope fails, which is answered by the message ID.
     */
    public function decode(AbstractType $pdu): LdapMessageRequest
    {
        $envelope = $this->envelopes->read($pdu);
        // Resolved before anything is decoded, so an unrecognized operation ends the session (RFC 4511 4.1.1).
        $operation = $this->operations[$envelope->operationTag]
            ?? throw $this->envelopes->unsupported($envelope->operationTag);
        $context = $this->contexts->create();

        [$request, $controls] = $this->envelopes->answerable(
            $envelope,
            fn(): array => [
                $operation->decode(
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

        return new LdapMessageRequest(
            $envelope->messageId,
            $request,
            ...$controls,
        );
    }
}
