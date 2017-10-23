<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Asn1\Type;

/**
 * Represents an ASN1 octet string type.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class OctetStringType extends AbstractStringType
{
    protected $tagNumber = self::TAG_TYPE_OCTET_STRING;

    /**
     * @param string $value
     * @return $this
     */
    public function setValue($value)
    {
        $this->value = $value;

        return $this;
    }
}
