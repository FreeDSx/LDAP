<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Asn1\Type;

/**
 * Represents an ASN1 octet string type.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class OctetStringType extends AbstractType
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
