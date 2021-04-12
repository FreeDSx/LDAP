<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Operation\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ProtocolException;

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
    public function getEntry(): Entry
    {
        return $this->entry;
    }

    /**
     * {@inheritDoc}
     * @return self
     */
    public static function fromAsn1(AbstractType $type)
    {
        $attributes = [];
        $dn = $type->getChild(0);
        if ($dn === null) {
            throw new ProtocolException('The search result entry is malformed.');
        }

        $partialAttributes = $type->getChild(1);
        if ($partialAttributes !== null) {
            foreach ($partialAttributes as $partialAttribute) {
                $values = [];
                /** @var SequenceType|null $attrValues */
                $attrValues = $partialAttribute->getChild(1);
                if ($attrValues !== null) {
                    foreach ($attrValues->getChildren() as $attrValue) {
                        /** @var OctetStringType $attrValue */
                        $values[] = $attrValue->getValue();
                    }
                }

                $attributes[] = new Attribute($partialAttribute->getChild(0)->getValue(), ...$values);
            }
        }

        return new self(new Entry(
            new Dn($dn->getValue()),
            ...$attributes
        ));
    }

    /**
     * @return SequenceType
     */
    public function toAsn1(): AbstractType
    {
        /** @var SequenceType $asn1 */
        $asn1 = Asn1::application(self::TAG_NUMBER, Asn1::sequence());

        $partialAttributes = Asn1::sequenceOf();
        foreach ($this->entry->getAttributes() as $attribute) {
            $partialAttributes->addChild(Asn1::sequence(
                Asn1::octetString($attribute->getDescription()),
                Asn1::setOf(...array_map(function ($v) {
                    return Asn1::octetString($v);
                }, $attribute->getValues()))
            ));
        }
        $asn1->addChild(Asn1::octetString($this->entry->getDn()->toString()));
        $asn1->addChild($partialAttributes);

        return $asn1;
    }
}
