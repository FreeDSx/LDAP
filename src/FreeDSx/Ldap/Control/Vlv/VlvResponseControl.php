<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Control\Vlv;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\EnumeratedType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * Represents a VLV Response. draft-ietf-ldapext-ldapv3-vlv-09
 *
 * VirtualListViewResponse ::= SEQUENCE {
 *     targetPosition    INTEGER (0 .. maxInt),
 *     contentCount     INTEGER (0 .. maxInt),
 *     virtualListViewResult ENUMERATED {
 *         success (0),
 *         operationsError (1),
 *         protocolError (3),
 *         unwillingToPerform (53),
 *         insufficientAccessRights (50),
 *         timeLimitExceeded (3),
 *         adminLimitExceeded (11),
 *         innapropriateMatching (18),
 *         sortControlMissing (60),
 *         offsetRangeError (61),
 *         other(80),
 *         ... },
 *     contextID     OCTET STRING OPTIONAL }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class VlvResponseControl extends Control
{
    use VlvTrait;

    /**
     * @var int
     */
    protected $result;

    /**
     * @param int $offset
     * @param int $count
     * @param int $result
     * @param null|string $contextId
     */
    public function __construct(int $offset, int $count, int $result, ?string $contextId = null)
    {
        $this->offset = $offset;
        $this->count = $count;
        $this->result = $result;
        $this->contextId = $contextId;
        parent::__construct(self::OID_VLV_RESPONSE);
    }

    /**
     * @return int
     */
    public function getResult(): int
    {
        return $this->result;
    }

    /**
     * @param AbstractType $type
     * @return Control
     * @throws ProtocolException
     * @throws \FreeDSx\Asn1\Exception\EncoderException
     * @throws \FreeDSx\Asn1\Exception\PartialPduException
     */
    public static function fromAsn1(AbstractType $type)
    {
        $vlv = self::decodeEncodedValue($type);

        if (!$vlv instanceof SequenceType) {
            throw new ProtocolException('The VLV response value contains an unexpected ASN1 type.');
        }
        $offset = $vlv->getChild(0);
        $count = $vlv->getChild(1);
        $result = $vlv->getChild(2);
        $contextId = $vlv->getChild(3);

        if (!$offset instanceof IntegerType) {
            throw new ProtocolException('The VLV response value contains an unexpected ASN1 type.');
        }
        if (!$count instanceof IntegerType) {
            throw new ProtocolException('The VLV response value contains an unexpected ASN1 type.');
        }
        if (!$result instanceof EnumeratedType) {
            throw new ProtocolException('The VLV response value contains an unexpected ASN1 type.');
        }
        if ($contextId !== null && !$contextId instanceof OctetStringType) {
            throw new ProtocolException('The VLV response value contains an unexpected ASN1 type.');
        }

        $response = new self(
            $offset->getValue(),
            $count->getValue(),
            $result->getValue()
        );
        if ($contextId !== null) {
            $response->contextId = $contextId->getValue();
        }

        return parent::mergeControlData($response, $type);
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->controlValue = Asn1::sequence(
            Asn1::integer((int) $this->offset),
            Asn1::integer((int) $this->count),
            Asn1::enumerated($this->result)
        );
        if ($this->contextId !== null) {
            $this->controlValue->addChild(new OctetStringType($this->contextId));
        }

        return parent::toAsn1();
    }
}
