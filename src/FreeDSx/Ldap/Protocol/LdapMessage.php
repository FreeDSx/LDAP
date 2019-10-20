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

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceOfType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request;
use FreeDSx\Ldap\Operation\Response;
use FreeDSx\Socket\PduInterface;

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
     * @var int
     */
    protected $messageId;

    /**
     * @var ControlBag
     */
    protected $controls;

    /**
     * @param int $messageId
     * @param Control\Control ...$controls
     */
    public function __construct(int $messageId, Control\Control ...$controls)
    {
        $this->messageId = $messageId;
        $this->controls = new ControlBag(...$controls);
    }

    /**
     * @return int
     */
    public function getMessageId(): int
    {
        return $this->messageId;
    }

    /**
     * Get the controls for this specific message.
     *
     * @return ControlBag
     */
    public function controls(): ControlBag
    {
        return $this->controls;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $asn1 = Asn1::sequence(
            Asn1::integer($this->messageId),
            $this->getOperationAsn1()
        );

        if (\count($this->controls->toArray()) !== 0) {
            /** @var SequenceOfType $controls */
            $controls = Asn1::context(0, Asn1::sequenceOf());
            foreach ($this->controls->toArray() as $control) {
                $controls->addChild($control->toAsn1());
            }
            $asn1->addChild($controls);
        }

        return $asn1;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        if (!$type instanceof SequenceType) {
            throw new ProtocolException(sprintf(
                'Expected an ASN1 sequence type, but got: %s',
                get_class($type)
            ));
        }
        $count = \count($type->getChildren());
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
                    /** @var \FreeDSx\Asn1\Type\IncompleteType $child */
                    $child = (new LdapEncoder())->complete($child, AbstractType::TAG_TYPE_SEQUENCE);
                    /** @var SequenceOfType $child */
                    foreach ($child->getChildren() as $control) {
                        if (!($control instanceof SequenceType && $control->getChild(0) !== null && $control->getChild(0) instanceof OctetStringType)) {
                            throw new ProtocolException('The control either is not a sequence or has no OID value attached.');
                        }
                        switch ($control->getChild(0)->getValue()) {
                            case Control\Control::OID_PAGING:
                                $controls[] = Control\PagingControl::fromAsn1($control);
                                break;
                            case Control\Control::OID_SORTING_RESPONSE:
                                $controls[] = Control\Sorting\SortingResponseControl::fromAsn1($control);
                                break;
                            case Control\Control::OID_VLV_RESPONSE:
                                $controls[] = Control\Vlv\VlvResponseControl::fromAsn1($control);
                                break;
                            case Control\Control::OID_DIR_SYNC:
                                $controls[] = Control\Ad\DirSyncResponseControl::fromAsn1($control);
                                break;
                            default:
                                $controls[] = Control\Control::fromAsn1($control);
                                break;
                        }
                    }
                }
            }
        }

        $messageId = $type->getChild(0);
        if (!($messageId !== null && $messageId instanceof IntegerType)) {
            throw new ProtocolException('Expected an LDAP message ID as an ASN.1 integer type. None received.');
        }
        $opAsn1 = $type->getChild(1);
        if ($opAsn1 === null) {
            throw new ProtocolException('The LDAP message is malformed.');
        }

        switch ($opAsn1->getTagNumber()) {
            case 0:
                $operation = Request\BindRequest::fromAsn1($opAsn1);
                break;
            case 1:
                $operation = Response\BindResponse::fromAsn1($opAsn1);
                break;
            case 2:
                $operation = Request\UnbindRequest::fromAsn1($opAsn1);
                break;
            case 3:
                $operation = Request\SearchRequest::fromAsn1($opAsn1);
                break;
            case 4:
                $operation = Response\SearchResultEntry::fromAsn1($opAsn1);
                break;
            case 5:
                $operation = Response\SearchResultDone::fromAsn1($opAsn1);
                break;
            case 6:
                $operation = Request\ModifyRequest::fromAsn1($opAsn1);
                break;
            case 7:
                $operation = Response\ModifyResponse::fromAsn1($opAsn1);
                break;
            case 8:
                $operation = Request\AddRequest::fromAsn1($opAsn1);
                break;
            case 9:
                $operation = Response\AddResponse::fromAsn1($opAsn1);
                break;
            case 10:
                $operation = Request\DeleteRequest::fromAsn1($opAsn1);
                break;
            case 11:
                $operation = Response\DeleteResponse::fromAsn1($opAsn1);
                break;
            case 12:
                $operation = Request\ModifyDnRequest::fromAsn1($opAsn1);
                break;
            case 13:
                $operation = Response\ModifyDnResponse::fromAsn1($opAsn1);
                break;
            case 14:
                $operation = Request\CompareRequest::fromAsn1($opAsn1);
                break;
            case 15:
                $operation = Response\CompareResponse::fromAsn1($opAsn1);
                break;
            case 19:
                $operation = Response\SearchResultReference::fromAsn1($opAsn1);
                break;
            case 23:
                $operation = Request\ExtendedRequest::fromAsn1($opAsn1);
                break;
            case 24:
                $operation = Response\ExtendedResponse::fromAsn1($opAsn1);
                break;
            case 25:
                $operation = Response\IntermediateResponse::fromAsn1($opAsn1);
                break;
            default:
                throw new ProtocolException(sprintf(
                    'The tag %s for the LDAP operation is not supported.',
                    $opAsn1->getTagNumber()
                ));
        }

        return new static(
            $messageId->getValue(),
            $operation,
            ...$controls
        );
    }

    /**
     * @return AbstractType
     */
    abstract protected function getOperationAsn1(): AbstractType;
}
