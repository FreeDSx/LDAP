<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\BooleanType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\ProtocolElementInterface;
use function count;

/**
 * Represents a control. RFC 4511, 4.1.11
 *
 * Control ::= SEQUENCE {
 *     controlType             LDAPOID,
 *     criticality             BOOLEAN DEFAULT FALSE,
 *     controlValue            OCTET STRING OPTIONAL }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Control implements ProtocolElementInterface
{
    public const OID_DIR_SYNC = '1.2.840.113556.1.4.841';

    public const OID_EXPECTED_ENTRY_COUNT = '1.2.840.113556.1.4.2211';

    public const OID_EXTENDED_DN = '1.2.840.113556.1.4.529';

    public const OID_PAGING = '1.2.840.113556.1.4.319';

    public const OID_POLICY_HINTS = '1.2.840.113556.1.4.2239';

    public const OID_PWD_POLICY = '1.3.6.1.4.1.42.2.27.8.5.1';

    public const OID_SET_OWNER = '1.2.840.113556.1.4.2255';

    public const OID_SD_FLAGS = '1.2.840.113556.1.4.801';

    public const OID_SHOW_DELETED = '1.2.840.113556.1.4.417';

    public const OID_SHOW_RECYCLED = '1.2.840.113556.1.4.2064';

    public const OID_SUBTREE_DELETE = '1.2.840.113556.1.4.805';

    public const OID_SORTING = '1.2.840.113556.1.4.473';

    public const OID_SORTING_RESPONSE = '1.2.840.113556.1.4.474';

    public const OID_VLV = '2.16.840.1.113730.3.4.9';

    public const OID_VLV_RESPONSE = '2.16.840.1.113730.3.4.10';

    protected string $controlType;

    protected bool $criticality;

    protected AbstractType|ProtocolElementInterface|string|null $controlValue;

    public function __construct(
        string $controlType,
        bool $criticality = false,
        AbstractType|ProtocolElementInterface|string|null $controlValue = null
    ) {
        $this->controlType = $controlType;
        $this->criticality = $criticality;
        $this->controlValue = $controlValue;
    }

    public function setTypeOid(string $oid): static
    {
        $this->controlType = $oid;

        return $this;
    }

    public function getTypeOid(): string
    {
        return $this->controlType;
    }

    public function setCriticality(bool $criticality): static
    {
        $this->criticality = $criticality;

        return $this;
    }

    public function getCriticality(): bool
    {
        return $this->criticality;
    }

    public function setValue(AbstractType|ProtocolElementInterface|string|null $controlValue): static
    {
        $this->controlValue = $controlValue;

        return $this;
    }

    public function getValue(): AbstractType|ProtocolElementInterface|string|null
    {
        return $this->controlValue;
    }

    /**
     * @inheritDoc
     */
    public function toAsn1(): AbstractType
    {
        $asn1 = Asn1::sequence(
            Asn1::octetString($this->controlType),
            Asn1::boolean($this->criticality)
        );

        if ($this->controlValue !== null) {
            $encoder = new LdapEncoder();
            if ($this->controlValue instanceof AbstractType) {
                $value = $encoder->encode($this->controlValue);
            } elseif ($this->controlValue instanceof ProtocolElementInterface) {
                $value = $encoder->encode($this->controlValue->toAsn1());
            } else {
                $value = $this->controlValue;
            }
            $asn1->addChild(Asn1::octetString($value));
        }

        return $asn1;
    }

    public function __toString(): string
    {
        return $this->controlType;
    }

    /**
     * {@inheritDoc}
     */
    public static function fromAsn1(AbstractType $type): static
    {
        if (!$type instanceof SequenceType) {
            throw new ProtocolException(sprintf(
                'Protocol encoding issue. Expected a sequence type but received: %s',
                get_class($type)
            ));
        }

        return new static(...self::parseAsn1ControlValues($type));
    }

    /**
     * @template T of Control
     * @param T $control
     * @return T
     * @throws ProtocolException
     */
    protected static function mergeControlData(
        $control,
        AbstractType $type
    ): Control {
        if (!($type instanceof SequenceType && count($type->getChildren()) <= 3)) {
            throw new ProtocolException(sprintf(
                'The received control is malformed. Expected at least 3 sequence values. Received %s.',
                count($type->getChildren())
            ));
        }
        [0 => $control->controlType, 1 => $control->criticality, 2 => $control->controlValue] = self::parseAsn1ControlValues($type);

        return $control;
    }

    /**
     * @throws ProtocolException
     * @throws EncoderException
     * @throws PartialPduException
     */
    protected static function decodeEncodedValue(AbstractType $type): AbstractType
    {
        if (!$type instanceof SequenceType) {
            throw new ProtocolException('The received control is malformed. Unable to get the encoded value.');
        }

        [2 => $value] = self::parseAsn1ControlValues($type);
        if ($value === null) {
            throw new ProtocolException('The received control is malformed. Unable to get the encoded value.');
        }

        return (new LdapEncoder())->decode($value);
    }

    /**
     * @return array{0: string, 1: bool, 2: string|null}
     */
    protected static function parseAsn1ControlValues(SequenceType $type): array
    {
        $oid = null;
        $criticality = false;
        $value = null;

        /*
         * RFC 4511, 4.1.1. States responses should not have criticality set, but not that it must not be set. So do not
         * assume the position of the octet string value. Accounts for the additional logic of the checks here.
         */
        foreach ($type->getChildren() as $i => $child) {
            if ($child->getTagClass() !== AbstractType::TAG_CLASS_UNIVERSAL) {
                continue;
            }

            if ($i === 0) {
                $oid = $child->getValue();
            } elseif ($child instanceof BooleanType) {
                $criticality = $child->getValue();
            } elseif ($child instanceof OctetStringType) {
                $value = $child->getValue();
            }
        }

        return [$oid, $criticality, $value];
    }
}
