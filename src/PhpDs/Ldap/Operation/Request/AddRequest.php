<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Operation\Request;

use PhpDs\Ldap\Asn1\Asn1;
use PhpDs\Ldap\Asn1\Type\AbstractType;
use PhpDs\Ldap\Entry\Attribute;
use PhpDs\Ldap\Entry\Entry;

/**
 * A request to add an entry to LDAP. RFC 4511, 4.7.
 *
 * AddRequest ::= [APPLICATION 8] SEQUENCE {
 *     entry           LDAPDN,
 *     attributes      AttributeList }
 *
 * AttributeList ::= SEQUENCE OF attribute Attribute
 *
 * PartialAttribute ::= SEQUENCE {
 *     type       AttributeDescription,
 *     vals       SET OF value AttributeValue }
 *
 * Attribute ::= PartialAttribute(WITH COMPONENTS {
 *     ...,
 *     vals (SIZE(1..MAX))})
 *
 * AttributeDescription ::= LDAPString
 *
 * AttributeValue ::= OCTET STRING
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class AddRequest implements RequestInterface
{
    protected const APP_TAG = 8;

    /**
     * @var Entry
     */
    protected $entry;

    /**
     * @param Entry $entry
     */
    public function __construct(Entry $entry)
    {
        $this->entry = $entry;
    }

    /**
     * @return Entry
     */
    public function getEntry() : Entry
    {
        return $this->entry;
    }

    /**
     * @param Entry $entry
     * @return $this
     */
    public function setEntry(Entry $entry)
    {
        $this->entry = $entry;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        // TODO: Implement fromAsn1() method.
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $attributeList = Asn1::sequenceOf();

        /** @var Attribute $attribute */
        foreach ($this->entry as $attribute) {
            $attr = Asn1::sequence(Asn1::ldapString($attribute->getName()));

            $attrValues = Asn1::setOf(...array_map(function ($value) {
                return Asn1::octetString($value);
            }, $attribute->getValues()));

            $attributeList->addChild($attr->addChild($attrValues));
        }

        return Asn1::application(self::APP_TAG, Asn1::sequence(
            Asn1::ldapDn($this->entry->getDn()->toString()),
            $attributeList
        ));
    }
}
