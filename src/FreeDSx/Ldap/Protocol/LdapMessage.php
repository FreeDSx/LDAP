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
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceOfType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Socket\PduInterface;
use FreeDSx\Ldap\Operation\Request;
use FreeDSx\Ldap\Operation\Response;

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
    public function getMessageId() : int
    {
        return $this->messageId;
    }

    /**
     * Get the controls for this specific message.
     *
     * @return ControlBag
     */
    public function controls() : ControlBag
    {
        return $this->controls;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1() : AbstractType
    {
        $asn1 = Asn1::sequence(
            Asn1::integer($this->messageId),
            $this->getOperationAsn1()
        );

        if (!empty($this->controls->toArray())) {
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
        self::validateAsn1($type);
        $controls = [];

        /** @var SequenceType $type */
        foreach ($type->getChildren() as $child) {
            if ($child->getTagClass() === AbstractType::TAG_CLASS_CONTEXT_SPECIFIC && $child->getTagNumber() === 0) {
                /** @var \FreeDSx\Asn1\Type\IncompleteType $child */
                $child = (new LdapEncoder())->complete($child, AbstractType::TAG_TYPE_SEQUENCE);
                /** @var SequenceOfType $child */
                foreach ($child->getChildren() as $control) {
                    $controls[] = self::constructControl($control);
                }
            }
        }

        return new static(
            $type->getChild(0)->getValue(),
            self::constructOperation($type->getChild(1)),
            ...$controls
        );
    }

    /**
     * @return AbstractType
     */
    abstract protected function getOperationAsn1() : AbstractType;

    /**
     * @param AbstractType $type
     * @throws ProtocolException
     */
    protected static function validateAsn1(AbstractType $type)
    {
        if (!$type instanceof SequenceType) {
            throw new ProtocolException(sprintf(
                'Expected an ASN1 sequence type, but got: %s',
                get_class($type)
            ));
        }
        if (\count($type->getChildren()) < 2) {
            throw new ProtocolException(sprintf(
                'Expected an ASN1 sequence with at least 2 elements, but it has %s',
                count($type->getChildren())
            ));
        }
        if (!$type->getChild(0) instanceof IntegerType) {
            throw new ProtocolException(sprintf(
                'Expected an LDAP message ID, but got: %s',
                get_class($type->getChild(0))
            ));
        }
    }

    /**
     * @param AbstractType $asn1
     * @return ProtocolElementInterface
     * @throws ProtocolException
     */
    protected static function constructOperation(AbstractType $asn1) : ProtocolElementInterface
    {
        switch ($asn1->getTagNumber()) {
            case 0:
                return Request\BindRequest::fromAsn1($asn1);
                break;
            case 1:
                return Response\BindResponse::fromAsn1($asn1);
                break;
            case 2:
                return Request\UnbindRequest::fromAsn1($asn1);
                break;
            case 3:
                return Request\SearchRequest::fromAsn1($asn1);
                break;
            case 4:
                return Response\SearchResultEntry::fromAsn1($asn1);
                break;
            case 5:
                return Response\SearchResultDone::fromAsn1($asn1);
                break;
            case 6:
                return Request\ModifyRequest::fromAsn1($asn1);
                break;
            case 7:
                return Response\ModifyResponse::fromAsn1($asn1);
                break;
            case 8:
                return Request\AddRequest::fromAsn1($asn1);
                break;
            case 9:
                return Response\AddResponse::fromAsn1($asn1);
                break;
            case 10:
                return Request\DeleteRequest::fromAsn1($asn1);
                break;
            case 11:
                return Response\DeleteResponse::fromAsn1($asn1);
                break;
            case 12:
                return Request\ModifyDnRequest::fromAsn1($asn1);
                break;
            case 13:
                return Response\ModifyDnResponse::fromAsn1($asn1);
                break;
            case 14:
                return Request\CompareRequest::fromAsn1($asn1);
                break;
            case 15:
                return Response\CompareResponse::fromAsn1($asn1);
                break;
            case 19:
                return Response\SearchResultReference::fromAsn1($asn1);
                break;
            case 23:
                return Request\ExtendedRequest::fromAsn1($asn1);
                break;
            case 24:
                return Response\ExtendedResponse::fromAsn1($asn1);
                break;
            case 25:
                return Response\IntermediateResponse::fromAsn1($asn1);
                break;
        }

        throw new ProtocolException(sprintf(
            'The tag %s for the LDAP operation is not supported.',
            $asn1->getTagNumber()
        ));
    }

    /**
     * @param AbstractType $asn1
     * @return Control\Control
     * @throws ProtocolException
     */
    protected static function constructControl(AbstractType $asn1) : Control\Control
    {
        if (!($asn1 instanceof SequenceType && $asn1->getChild(0) && $asn1->getChild(0) instanceof OctetStringType)) {
            throw new ProtocolException('The control either is not a sequence or has no OID value attached.');
        }

        $oid = $asn1->getChild(0)->getValue();
        switch ($oid) {
            case Control\Control::OID_PAGING:
                return Control\PagingControl::fromAsn1($asn1);
                break;
            case Control\Control::OID_SORTING_RESPONSE;
                return Control\Sorting\SortingResponseControl::fromAsn1($asn1);
                break;
            case Control\Control::OID_VLV_RESPONSE:
                return Control\Vlv\VlvResponseControl::fromAsn1($asn1);
                break;
            case Control\Control::OID_DIR_SYNC:
                return Control\Ad\DirSyncResponseControl::fromAsn1($asn1);
                break;
            default:
                return Control\Control::fromAsn1($asn1);
                break;
        }
    }
}
