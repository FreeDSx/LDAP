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
use FreeDSx\Ldap\Asn1\Encoder\BerEncoder;
use FreeDSx\Ldap\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Asn1\Type\OctetStringType;
use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * Checks for the presence of an attribute (ie. whether or not it contains a value). RFC 4511, 4.5.1.7.5
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PresentFilter implements FilterInterface
{
    use FilterAttributeTrait;

    protected const APP_TAG = 7;

    /**
     * @param string $attribute
     */
    public function __construct(string $attribute)
    {
        $this->attribute = $attribute;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1() : AbstractType
    {
        return Asn1::context(self::APP_TAG, Asn1::ldapString($this->attribute));
    }

    /**
     * {@inheritdoc}
     */
    public function toString() : string
    {
        return self::PAREN_LEFT.$this->attribute.self::FILTER_EQUAL.'*'.self::PAREN_RIGHT;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        $type = $type instanceof IncompleteType ? (new BerEncoder())->complete($type, AbstractType::TAG_TYPE_OCTET_STRING) : $type;
        if (!($type instanceof OctetStringType)) {
            throw new ProtocolException('The present filter is malformed');
        }

        return new self($type->getValue());
    }
}
