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

namespace FreeDSx\Ldap\Operation\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Helper\AttributeEntryMessage;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Asn1\Type\SetOfType;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;

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
    public const TAG_NUMBER = 4;

    public function __construct(private readonly Entry $entry) {}

    public function getEntry(): Entry
    {
        return $this->entry;
    }

    /**
     * Builds the entry from a message decoded directly from BER, which bypasses the ASN.1 type graph.
     */
    public static function fromAttributeEntry(AttributeEntryMessage $message): self
    {
        $attributes = [];

        foreach ($message->attributes as [$description, $values]) {
            $attributes[] = Attribute::fromArray(
                $description,
                $values,
            );
        }

        return new self(Entry::raw(
            new Dn($message->primaryId),
            $attributes,
        ));
    }

    public function toAsn1(): SequenceType
    {
        /** @var SequenceType $asn1 */
        $asn1 = Asn1::application(
            tagNumber: self::TAG_NUMBER,
            type: Asn1::sequence(),
        );

        $partialAttributes = Asn1::sequenceOf();
        foreach ($this->entry->getAttributes() as $attribute) {
            $values = [];
            foreach ($attribute->getValues() as $value) {
                $values[] = Asn1::octetString($value);
            }
            $partialAttributes->addChild(Asn1::sequence(
                Asn1::octetString($attribute->getDescription()),
                SetOfType::fromChildren($values),
            ));
        }
        $asn1->addChild(Asn1::octetString($this->entry->getDn()->toString()));
        $asn1->addChild($partialAttributes);

        return $asn1;
    }
}
