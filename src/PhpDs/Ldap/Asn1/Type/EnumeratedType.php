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
 * Represents an ASN1 enumerated type.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class EnumeratedType extends AbstractType
{
    protected $tagNumber = self::TAG_TYPE_ENUMERATED;

    /**
     * EnumeratedType constructor.
     * @param int $enumValue
     */
    public function __construct(int $enumValue)
    {
        parent::__construct($enumValue);
    }

    /**
     * @param int $value
     * @return $this
     */
    public function setValue(int $value)
    {
        $this->value = $value;

        return $this;
    }
}
