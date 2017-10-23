<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Operation\Response;

use PhpDs\Ldap\Asn1\Asn1;
use PhpDs\Ldap\Asn1\Type\AbstractType;
use PhpDs\Ldap\Asn1\Type\SequenceType;
use PhpDs\Ldap\Entry\Attribute;
use PhpDs\Ldap\Entry\Entry;

/**
 * A search result entry. RFC 4511, 4.5.2.
 *
 * SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
 *     objectName      LDAPDN,
 *     attributes      PartialAttributeList }
 *
 * PartialAttributeList ::= SEQUENCE OF
 *     partialAttribute PartialAttribute
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SearchResultEntry implements ResponseInterface
{
    protected const TAG_NUMBER = 4;

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
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        $attributes = [];

        /** @var \PhpDs\Ldap\Asn1\Type\SequenceType $type */
        foreach ($type->getChild(1)->getChildren() as $partialAttribute) {
            $values = [];

            /** @var \PhpDs\Ldap\Asn1\Type\SequenceType $partialAttribute */
            foreach ($partialAttribute->getChild(1)->getChildren() as $attrValue) {
                /** @var \PhpDs\Ldap\Asn1\Type\OctetStringType $attrValue */
                $values[] = $attrValue->getValue();
            }

            $attributes[] = new Attribute($partialAttribute->getChild(0)->getValue(), ...$values);
        }

        return new self(new Entry($type->getChild(0)->getValue(), ...$attributes));
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        /** @var SequenceType $asn1 */
        $asn1 = Asn1::application(self::TAG_NUMBER, Asn1::sequence());

        $asn1->addChild(Asn1::ldapDn($this->entry->getDn()->toString()));
        foreach ($this->entry->getAttributes() as $attribute) {
            $asn1->addChild(Asn1::sequence(
                Asn1::ldapString($attribute->getName()),
                Asn1::setOf(...array_map(function ($v) {
                    return Asn1::octetString($v);
                }, $attribute->getValues()))
            ));
        }

        return $asn1;
    }
}
