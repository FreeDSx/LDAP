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

namespace FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\ProtocolElementInterface;
use Stringable;

/**
 * Represents a control. RFC 4511, 4.1.11
 *
 * Control ::= SEQUENCE {
 *     controlType             LDAPOID,
 *     criticality             BOOLEAN DEFAULT FALSE,
 *     controlValue            OCTET STRING OPTIONAL }
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Control implements ProtocolElementInterface, Stringable
{
    public const OID_ASSERTION = '1.3.6.1.1.12';

    public const OID_DIR_SYNC = '1.2.840.113556.1.4.841';

    public const OID_EXPECTED_ENTRY_COUNT = '1.2.840.113556.1.4.2211';

    public const OID_EXTENDED_DN = '1.2.840.113556.1.4.529';

    public const OID_MANAGE_DSA_IT = '2.16.840.1.113730.3.4.2';

    public const OID_PAGING = '1.2.840.113556.1.4.319';

    public const OID_POLICY_HINTS = '1.2.840.113556.1.4.2239';

    public const OID_POST_READ = '1.3.6.1.1.13.2';

    public const OID_PRE_READ = '1.3.6.1.1.13.1';

    public const OID_PROXY_AUTHORIZATION = '2.16.840.1.113730.3.4.18';

    public const OID_PWD_POLICY = '1.3.6.1.4.1.42.2.27.8.5.1';

    public const OID_RELAX_RULES = '1.3.6.1.4.1.4203.666.5.12';

    public const OID_SET_OWNER = '1.2.840.113556.1.4.2255';

    public const OID_SD_FLAGS = '1.2.840.113556.1.4.801';

    public const OID_SHOW_DELETED = '1.2.840.113556.1.4.417';

    public const OID_SHOW_RECYCLED = '1.2.840.113556.1.4.2064';

    public const OID_SUBENTRIES = '1.3.6.1.4.1.4203.1.10.1';

    public const OID_SYNC_REQUEST = '1.3.6.1.4.1.4203.1.9.1.1';

    public const OID_SYNC_STATE = '1.3.6.1.4.1.4203.1.9.1.2';

    public const OID_SYNC_DONE = '1.3.6.1.4.1.4203.1.9.1.3';

    public const OID_SUBTREE_DELETE = '1.2.840.113556.1.4.805';

    public const OID_SUBTREE_DELETE_PROGRESS = '1.3.6.1.4.1.66207.1.3.1';

    public const OID_SORTING = '1.2.840.113556.1.4.473';

    public const OID_SORTING_RESPONSE = '1.2.840.113556.1.4.474';

    public const OID_VLV = '2.16.840.1.113730.3.4.9';

    public const OID_VLV_RESPONSE = '2.16.840.1.113730.3.4.10';

    /**
     * @param AbstractType<mixed>|ProtocolElementInterface|string|null $controlValue
     */
    public function __construct(
        private string $controlType,
        private bool $criticality = false,
        protected AbstractType|ProtocolElementInterface|string|null $controlValue = null,
    ) {}

    public function __toString(): string
    {
        return $this->controlType;
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

    /**
     * @param AbstractType<mixed>|ProtocolElementInterface|string|null $controlValue
     */
    public function setValue(AbstractType|ProtocolElementInterface|string|null $controlValue): static
    {
        $this->controlValue = $controlValue;

        return $this;
    }

    /**
     * @return AbstractType<mixed>|ProtocolElementInterface|string|null
     */
    public function getValue(): AbstractType|ProtocolElementInterface|string|null
    {
        return $this->controlValue;
    }

    public function toAsn1(): SequenceType
    {
        $asn1 = Asn1::sequence(
            Asn1::octetString($this->controlType),
        );
        // RFC 4511 5.1: a field holding its default value is absent from the encoding.
        if ($this->criticality) {
            $asn1->addChild(Asn1::boolean(true));
        }

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
}
