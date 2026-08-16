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
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceOfType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Exception\InvalidDnSyntaxException;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request;
use FreeDSx\Ldap\Operation\Response;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Socket\PduInterface;

use function count;

/**
 * The LDAP Message envelope (PDU). RFC 4511, 4.1.1
 *
 * LDAPMessage ::= SEQUENCE {
 *     messageID       MessageID,
 *     protocolOp      CHOICE {
 *         bindRequest           BindRequest,
 *         bindResponse          BindResponse,
 *         unbindRequest         UnbindRequest,
 *         searchRequest         SearchRequest,
 *         searchResEntry        SearchResultEntry,
 *         searchResDone         SearchResultDone,
 *         searchResRef          SearchResultReference,
 *         modifyRequest         ModifyRequest,
 *         modifyResponse        ModifyResponse,
 *         addRequest            AddRequest,
 *         addResponse           AddResponse,
 *         delRequest            DelRequest,
 *         delResponse           DelResponse,
 *         modDNRequest          ModifyDNRequest,
 *         modDNResponse         ModifyDNResponse,
 *         compareRequest        CompareRequest,
 *         compareResponse       CompareResponse,
 *         abandonRequest        AbandonRequest,
 *         extendedReq           ExtendedRequest,
 *         extendedResp          ExtendedResponse,
 *         ...,
 *         intermediateResponse  IntermediateResponse },
 *     controls       [0] Controls OPTIONAL }
 *
 * MessageID ::= INTEGER (0 ..  maxInt)
 *
 * maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
abstract class LdapMessage implements ProtocolElementInterface, PduInterface
{
    /**
     * The upper bound every RFC 4511 INTEGER (0 .. maxInt) field shares.
     */
    public const MAX_INT = 2147483647;

    /**
     * Every protocolOp tag this implementation decodes, keyed by tag.
     *
     * @var array<int, class-string<ProtocolElementInterface>>
     */
    private const PROTOCOL_OPS = [
        0 => Request\BindRequest::class,
        1 => Response\BindResponse::class,
        2 => Request\UnbindRequest::class,
        3 => Request\SearchRequest::class,
        4 => Response\SearchResultEntry::class,
        5 => Response\SearchResultDone::class,
        6 => Request\ModifyRequest::class,
        7 => Response\ModifyResponse::class,
        8 => Request\AddRequest::class,
        9 => Response\AddResponse::class,
        10 => Request\DeleteRequest::class,
        11 => Response\DeleteResponse::class,
        12 => Request\ModifyDnRequest::class,
        13 => Response\ModifyDnResponse::class,
        14 => Request\CompareRequest::class,
        15 => Response\CompareResponse::class,
        16 => Request\AbandonRequest::class,
        19 => Response\SearchResultReference::class,
        23 => Request\ExtendedRequest::class,
        24 => Response\ExtendedResponse::class,
        25 => Response\IntermediateResponse::class,
    ];

    private ControlBag $controls;

    public function __construct(
        private readonly int $messageId,
        Control\Control ...$controls,
    ) {
        $this->controls = new ControlBag(...$controls);
    }

    public function getMessageId(): int
    {
        return $this->messageId;
    }

    /**
     * Get the controls for this specific message.
     */
    public function controls(): ControlBag
    {
        return $this->controls;
    }

    /**
     * @throws EncoderException
     */
    public function toAsn1(): SequenceType
    {
        $asn1 = Asn1::sequence(
            Asn1::integer($this->messageId),
            $this->getOperationAsn1(),
        );

        if (count($this->controls->toArray()) !== 0) {
            /** @var SequenceOfType $controls */
            $controls = Asn1::context(
                tagNumber: 0,
                type: Asn1::sequenceOf(),
            );
            foreach ($this->controls->toArray() as $control) {
                $controls->addChild($control->toAsn1());
            }
            $asn1->addChild($controls);
        }

        return $asn1;
    }

    /**
     * {@inheritDoc}
     *
     * @param AbstractType<mixed> $type
     * @throws EncoderException
     * @throws PartialPduException
     * @throws RuntimeException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        if (!$type instanceof SequenceType) {
            throw new ProtocolException(sprintf(
                'Expected an ASN1 sequence type, but got: %s',
                get_class($type),
            ));
        }
        $count = count($type->getChildren());
        if ($count < 2) {
            throw new ProtocolException(sprintf(
                'Expected an ASN1 sequence with at least 2 elements, but it has %s',
                count($type->getChildren()),
            ));
        }

        $messageId = $type->getChild(0);
        if (!($messageId instanceof IntegerType)) {
            throw new ProtocolException('Expected an LDAP message ID as an ASN.1 integer type. None received.');
        }

        $messageIdValue = $messageId->getValue();
        if (!is_int($messageIdValue)) {
            throw new ProtocolException('Expected an LDAP message ID as an ASN.1 integer type. None received.');
        }

        // A value outside the range MessageID constrains is not an encoding of that type, so it cannot be parsed
        // as one. Answering it would mean echoing an ID no conformant peer can accept.
        if ($messageIdValue < 0 || $messageIdValue > self::MAX_INT) {
            throw new ProtocolException('The LDAP message ID is outside the range it is permitted to use.');
        }
        /** @var SequenceType|null $opAsn1 */
        $opAsn1 = $type->getChild(1);
        if ($opAsn1 === null) {
            throw new ProtocolException('The LDAP message is malformed.');
        }

        $opTag = $opAsn1->getTagNumber();

        // Resolved before anything is decoded: an unrecognized operation ends the session (RFC 4511 4.1.1),
        // so it must not reach the answerable path below.
        if (!is_int($opTag) || !isset(self::PROTOCOL_OPS[$opTag])) {
            throw new ProtocolException(sprintf(
                'The tag %s for the LDAP operation is not supported.',
                (string) $opTag,
            ));
        }

        // Past this point the message can be answered by its ID, so a failure inside is reported as one that
        // names the message rather than one that ends the session.
        try {
            $operation = self::PROTOCOL_OPS[$opTag]::fromAsn1($opAsn1);
            $controls = self::controlsFromAsn1(
                $type,
                $count,
            );
        } catch (InvalidDnSyntaxException $e) {
            throw new MessageDecodeException(
                $messageIdValue,
                $opTag,
                $e->getMessage(),
                $e,
                ResultCode::INVALID_DN_SYNTAX,
            );
        } catch (ProtocolException|EncoderException $e) {
            throw new MessageDecodeException(
                $messageIdValue,
                $opTag,
                $e->getMessage(),
                $e,
            );
        }

        return new static(
            $messageIdValue,
            $operation,
            ...$controls,
        );
    }

    /**
     * Subclasses override to honor direction-specific OIDs, e.g. controls whose request and response forms differ.
     */
    protected static function controlFromAsn1(SequenceType $control): Control\Control
    {
        return match ($control->getChild(0)?->getValue()) {
            Control\Control::OID_PAGING => Control\PagingControl::fromAsn1($control),
            Control\Control::OID_SORTING => Control\Sorting\SortingControl::fromAsn1($control),
            Control\Control::OID_SORTING_RESPONSE => Control\Sorting\SortingResponseControl::fromAsn1($control),
            Control\Control::OID_VLV_RESPONSE => Control\Vlv\VlvResponseControl::fromAsn1($control),
            Control\Control::OID_DIR_SYNC => Control\Ad\DirSyncResponseControl::fromAsn1($control),
            Control\Control::OID_SYNC_STATE => Control\Sync\SyncStateControl::fromAsn1($control),
            Control\Control::OID_SYNC_REQUEST => Control\Sync\SyncRequestControl::fromAsn1($control),
            Control\Control::OID_SYNC_DONE => Control\Sync\SyncDoneControl::fromAsn1($control),
            Control\Control::OID_PROXY_AUTHORIZATION => Control\ProxyAuthorizationControl::fromAsn1($control),
            Control\Control::OID_ASSERTION => Control\AssertionControl::fromAsn1($control),
            Control\Control::OID_PRE_READ => Control\ReadEntry\PreReadControl::fromAsn1($control),
            Control\Control::OID_POST_READ => Control\ReadEntry\PostReadControl::fromAsn1($control),
            Control\Control::OID_SUBENTRIES => Control\SubentriesControl::fromAsn1($control),
            default => Control\Control::fromAsn1($control),
        };
    }

    /**
     * @return AbstractType<mixed>
     */
    abstract protected function getOperationAsn1(): AbstractType;

    /**
     * @param SequenceType<mixed> $type
     *
     * @return list<Control\Control>
     *
     * @throws ProtocolException
     * @throws EncoderException
     */
    private static function controlsFromAsn1(
        SequenceType $type,
        int $count,
    ): array {
        $controls = [];

        for ($i = 2; $i < $count; $i++) {
            $child = $type->getChild($i);
            if ($child === null || $child->getTagClass() !== AbstractType::TAG_CLASS_CONTEXT_SPECIFIC || $child->getTagNumber() !== 0) {
                continue;
            }
            if (!$child instanceof IncompleteType) {
                throw new ProtocolException('The ASN1 structure for the controls is malformed.');
            }

            $child = (new LdapEncoder())->complete(
                $child,
                AbstractType::TAG_TYPE_SEQUENCE,
            );

            foreach ($child->getChildren() as $control) {
                if (!($control instanceof SequenceType && $control->getChild(0) !== null && $control->getChild(0) instanceof OctetStringType)) {
                    throw new ProtocolException('The control either is not a sequence or has no OID value attached.');
                }
                $controls[] = static::controlFromAsn1($control);
            }
        }

        return $controls;
    }
}
