<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Control\Ad;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * Implements the AD SetOwner control.
 *
 *   SID octetString
 *
 * https://msdn.microsoft.com/en-us/library/dn392490.aspx
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SetOwnerControl extends Control
{
    private string $sid;

    public function __construct(string $sid)
    {
        $this->sid = $sid;
        parent::__construct(
            self::OID_SET_OWNER,
            true
        );
    }

    public function setSid(string $sid): self
    {
        $this->sid = $sid;

        return $this;
    }

    public function getSid(): string
    {
        return $this->sid;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->controlValue = Asn1::octetString($this->sid);

        return parent::toAsn1();
    }

    /**
     * {@inheritDoc}
     * @throws EncoderException
     * @throws PartialPduException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        $request = self::decodeEncodedValue($type);
        if (!$request instanceof OctetStringType) {
            throw new ProtocolException('A SetOwner control value must be an octet string type.');
        }
        $control = new static($request->getValue());

        return self::mergeControlData(
            $control,
            $type
        );
    }
}
