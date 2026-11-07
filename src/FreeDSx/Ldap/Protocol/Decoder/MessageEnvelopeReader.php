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

use Closure;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\AnswerableExceptionInterface;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\LdapMessage;

use function count;
use function is_int;
use function sprintf;

/**
 * Reads a received message's envelope, and keeps every failure past it answerable by the message's ID.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class MessageEnvelopeReader
{
    /**
     * RFC 4511 4.1.1 ends the session over a failure here, since nothing past it could be answered.
     *
     * @param AbstractType<mixed> $pdu
     * @throws ProtocolException
     */
    public function read(AbstractType $pdu): MessageEnvelope
    {
        if (!$pdu instanceof SequenceType) {
            throw new ProtocolException(sprintf(
                'Expected an ASN1 sequence type, but got: %s',
                $pdu::class,
            ));
        }
        $count = count($pdu->getChildren());
        if ($count < 2) {
            throw new ProtocolException(sprintf(
                'Expected an ASN1 sequence with at least 2 elements, but it has %s',
                $count,
            ));
        }

        $messageId = $this->messageIdOf($pdu);
        $operation = $pdu->getChild(1);
        if ($operation === null) {
            throw new ProtocolException('The LDAP message is malformed.');
        }
        $operationTag = $operation->getTagNumber();
        if (!is_int($operationTag)) {
            throw $this->unsupported($operationTag);
        }

        return new MessageEnvelope(
            $pdu,
            $messageId,
            $operationTag,
            $operation,
        );
    }

    /**
     * The refusal for an operation this side does not decode, which RFC 4511 4.1.1 answers by ending the session.
     */
    public function unsupported(int|string|null $operationTag): ProtocolException
    {
        return new ProtocolException(sprintf(
            'The tag %s for the LDAP operation is not supported.',
            (string) $operationTag,
        ));
    }

    /**
     * Runs the decoding past the envelope, so any failure in it names the message and the operation it belongs to.
     *
     * @template T
     * @param Closure(): T $decode
     * @return T
     * @throws MessageDecodeException
     */
    public function answerable(
        MessageEnvelope $envelope,
        Closure $decode,
    ): mixed {
        try {
            return $decode();
        } catch (AnswerableExceptionInterface $e) {
            throw new MessageDecodeException(
                $envelope->messageId,
                $envelope->operationTag,
                $e->getDiagnostic(),
                $e,
                $e->getCode(),
            );
        } catch (ProtocolException|EncoderException $e) {
            throw new MessageDecodeException(
                $envelope->messageId,
                $envelope->operationTag,
                $e->getMessage(),
                $e,
            );
        }
    }

    /**
     * Decodes each control the message carries, in order, with the decoder this side uses for one.
     *
     * @param Closure(SequenceType): Control $decode
     * @return list<Control>
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function controlsOf(
        MessageEnvelope $envelope,
        DecodeContext $context,
        Closure $decode,
    ): array {
        $controls = [];
        $count = count($envelope->pdu->getChildren());

        for ($i = 2; $i < $count; $i++) {
            $child = $envelope->pdu->getChild($i);
            if (
                $child === null
                || $child->getTagClass() !== AbstractType::TAG_CLASS_CONTEXT_SPECIFIC
                || $child->getTagNumber() !== 0
            ) {
                continue;
            }
            if (!$child instanceof IncompleteType) {
                throw new ProtocolException('The ASN1 structure for the controls is malformed.');
            }

            $controls = [
                ...$controls,
                ...$this->decodeControls(
                    $context->complete(
                        $child,
                        AbstractType::TAG_TYPE_SEQUENCE,
                    ),
                    $decode,
                ),
            ];
        }

        return $controls;
    }

    /**
     * @throws ProtocolException
     */
    private function messageIdOf(SequenceType $pdu): int
    {
        $messageId = $pdu->getChild(0);
        if (!($messageId instanceof IntegerType)) {
            throw new ProtocolException('Expected an LDAP message ID as an ASN.1 integer type. None received.');
        }

        $messageIdValue = $messageId->getValue();
        if (!is_int($messageIdValue)) {
            throw new ProtocolException('Expected an LDAP message ID as an ASN.1 integer type. None received.');
        }

        // An ID outside the range MessageID allows cannot be echoed back in a response any conformant peer accepts.
        if ($messageIdValue < 0 || $messageIdValue > LdapMessage::MAX_INT) {
            throw new ProtocolException('The LDAP message ID is outside the range it is permitted to use.');
        }

        return $messageIdValue;
    }

    /**
     * @param AbstractType<mixed> $controls
     * @param Closure(SequenceType): Control $decode
     * @return list<Control>
     * @throws ProtocolException
     */
    private function decodeControls(
        AbstractType $controls,
        Closure $decode,
    ): array {
        $decoded = [];
        foreach ($controls->getChildren() as $control) {
            if (!($control instanceof SequenceType && $control->getChild(0) instanceof OctetStringType)) {
                throw new ProtocolException('The control either is not a sequence or has no OID value attached.');
            }
            $decoded[] = $decode($control);
        }

        return $decoded;
    }
}
