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

namespace FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Asn1\Type\SetOfType;
use FreeDSx\Ldap\Entry\Entry;

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
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class AddRequest implements RequestInterface
{
    protected const APP_TAG = 8;

    public function __construct(private Entry $entry) {}

    public function getEntry(): Entry
    {
        return $this->entry;
    }

    public function setEntry(Entry $entry): self
    {
        $this->entry = $entry;

        return $this;
    }

    public function toAsn1(): SequenceType
    {
        $attributeList = Asn1::sequenceOf();

        foreach ($this->entry->getAttributes() as $attribute) {
            $attr = Asn1::sequence(Asn1::octetString($attribute->getDescription()));

            $attrValues = [];
            foreach ($attribute->getValues() as $value) {
                $attrValues[] = Asn1::octetString($value);
            }

            $attributeList->addChild($attr->addChild(SetOfType::fromChildren($attrValues)));
        }

        return Asn1::application(self::APP_TAG, Asn1::sequence(
            Asn1::octetString($this->entry->getDn()->toString()),
            $attributeList,
        ));
    }
}
