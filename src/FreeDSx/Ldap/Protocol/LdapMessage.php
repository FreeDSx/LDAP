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
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request;
use FreeDSx\Ldap\Operation\Response;
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
    private ControlBag $controls;

    public function __construct(
        private readonly int $messageId,
        Control\Control ...$controls
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
            $this->getOperationAsn1()
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
     * @throws EncoderException
     * @throws PartialPduException
     * @throws RuntimeException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        if (!$type instanceof SequenceType) {
            throw new ProtocolException(sprintf(
                'Expected an ASN1 sequence type, but got: %s',
                get_class($type)
            ));
        }
        $count = count($type->getChildren());
        if ($count < 2) {
            throw new ProtocolException(sprintf(
                'Expected an ASN1 sequence with at least 2 elements, but it has %s',
                count($type->getChildren())
            ));
        }

        $controls = [];
        if ($count > 2) {
            for ($i = 2; $i < $count; $i++) {
                $child = $type->getChild($i);
                if ($child !== null && $child->getTagClass() === AbstractType::TAG_CLASS_CONTEXT_SPECIFIC && $child->getTagNumber() === 0) {
                    if (!$child instanceof IncompleteType) {
                        throw new ProtocolException('The ASN1 structure for the controls is malformed.');
                    }
                    $child = (new LdapEncoder())->complete(
                        $child,
                        AbstractType::TAG_TYPE_SEQUENCE
                    );

                    foreach ($child->getChildren() as $control) {
                        if (!($control instanceof SequenceType && $control->getChild(0) !== null && $control->getChild(0) instanceof OctetStringType)) {
                            throw new ProtocolException('The control either is not a sequence or has no OID value attached.');
                        }
                        $controls[] = match ($control->getChild(0)->getValue()) {
                            Control\Control::OID_PAGING => Control\PagingControl::fromAsn1($control),
                            Control\Control::OID_SORTING_RESPONSE => Control\Sorting\SortingResponseControl::fromAsn1($control),
                            Control\Control::OID_VLV_RESPONSE => Control\Vlv\VlvResponseControl::fromAsn1($control),
                            Control\Control::OID_DIR_SYNC => Control\Ad\DirSyncResponseControl::fromAsn1($control),
                            Control\Control::OID_SYNC_STATE => Control\Sync\SyncStateControl::fromAsn1($control),
                            Control\Control::OID_SYNC_REQUEST => Control\Sync\SyncRequestControl::fromAsn1($control),
                            Control\Control::OID_SYNC_DONE => Control\Sync\SyncDoneControl::fromAsn1($control),
                            default => Control\Control::fromAsn1($control),
                        };
                    }
                }
            }
        }

        $messageId = $type->getChild(0);
        if (!($messageId instanceof IntegerType)) {
            throw new ProtocolException('Expected an LDAP message ID as an ASN.1 integer type. None received.');
        }
        /** @var SequenceType|null $opAsn1 */
        $opAsn1 = $type->getChild(1);
        if ($opAsn1 === null) {
            throw new ProtocolException('The LDAP message is malformed.');
        }

        $operation = match ($opAsn1->getTagNumber()) {
            0 => Request\BindRequest::fromAsn1($opAsn1),
            1 => Response\BindResponse::fromAsn1($opAsn1),
            2 => Request\UnbindRequest::fromAsn1($opAsn1),
            3 => Request\SearchRequest::fromAsn1($opAsn1),
            4 => Response\SearchResultEntry::fromAsn1($opAsn1),
            5 => Response\SearchResultDone::fromAsn1($opAsn1),
            6 => Request\ModifyRequest::fromAsn1($opAsn1),
            7 => Response\ModifyResponse::fromAsn1($opAsn1),
            8 => Request\AddRequest::fromAsn1($opAsn1),
            9 => Response\AddResponse::fromAsn1($opAsn1),
            10 => Request\DeleteRequest::fromAsn1($opAsn1),
            11 => Response\DeleteResponse::fromAsn1($opAsn1),
            12 => Request\ModifyDnRequest::fromAsn1($opAsn1),
            13 => Response\ModifyDnResponse::fromAsn1($opAsn1),
            14 => Request\CompareRequest::fromAsn1($opAsn1),
            15 => Response\CompareResponse::fromAsn1($opAsn1),
            19 => Response\SearchResultReference::fromAsn1($opAsn1),
            23 => Request\ExtendedRequest::fromAsn1($opAsn1),
            24 => Response\ExtendedResponse::fromAsn1($opAsn1),
            25 => Response\IntermediateResponse::fromAsn1($opAsn1),
            default => throw new ProtocolException(sprintf(
                'The tag %s for the LDAP operation is not supported.',
                $opAsn1->getTagNumber()
            )),
        };

        return new static(
            $messageId->getValue(),
            $operation,
            ...$controls
        );
    }

    abstract protected function getOperationAsn1(): AbstractType;
}
