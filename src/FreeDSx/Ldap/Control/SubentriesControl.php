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
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\BooleanType;
use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * Represents a subentries control. RFC 3672.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SubentriesControl extends Control
{
    protected $isVisible;

    /**
     * @param bool $isVisible
     */
    public function __construct(bool $isVisible = true)
    {
        $this->isVisible = $isVisible;
        parent::__construct(
            self::OID_SUBENTRIES,
            true
        );
    }

    /**
     * @return bool
     */
    public function getIsVisible() : bool
    {
        return $this->isVisible;
    }

    /**
     * @param bool $isVisible
     * @return $this
     */
    public function setIsVisible(bool $isVisible)
    {
        $this->isVisible = $isVisible;

        return $this;
    }

    public function toAsn1(): AbstractType
    {
        $this->controlValue = Asn1::boolean($this->isVisible);

        return parent::toAsn1();
    }

    public static function fromAsn1(AbstractType $type)
    {
        $isVisible = self::decodeEncodedValue($type);
        if (!$isVisible instanceof BooleanType) {
            throw new ProtocolException('Expected a boolean type for a subentries control value.');
        }

        return self::mergeControlData(new self($isVisible->getValue()), $type);
    }
}
