<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Search\Filter;

use FreeDSx\Ldap\Asn1\Asn1;
use FreeDSx\Ldap\Asn1\Type\AbstractType;

/**
 * Common methods for filters using attribute value assertions.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait AttributeValueAssertionTrait
{
    use FilterAttributeTrait;

    /**
     * @var string
     */
    protected $value;

    /**
     * @param string $attribute
     * @param string $value
     */
    public function __construct(string $attribute, string $value)
    {
        $this->attribute = $attribute;
        $this->value = $value;
    }

    /**
     * @param string $value
     * @return $this
     */
    public function setValue(string $value)
    {
        $this->value = $value;

        return $this;
    }

    /**
     * @return string
     */
    public function getValue() : string
    {
        return $this->value;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1() : AbstractType
    {
        return Asn1::context(self::CHOICE_TAG, Asn1::sequence(
            Asn1::ldapString($this->attribute),
            Asn1::octetString($this->value)
        ));
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        /** @var \FreeDSx\Ldap\Asn1\Type\SequenceType $type */
        new self(
            $type->getChild(0)->getValue(),
            $type->getChild(1)->getValue()
        );
    }
}
