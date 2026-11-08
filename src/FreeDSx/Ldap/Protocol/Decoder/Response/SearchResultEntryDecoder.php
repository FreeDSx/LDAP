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

namespace FreeDSx\Ldap\Protocol\Decoder\Response;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Asn1\Type\SetType;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\FieldValueTrait;
use FreeDSx\Ldap\Protocol\Decoder\OperationDecoderInterface;

/**
 * Decodes a search result entry (RFC 4511 4.5.2), which a read-entry response control also carries.
 *
 * @implements OperationDecoderInterface<SearchResultEntry>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SearchResultEntryDecoder implements OperationDecoderInterface
{
    use FieldValueTrait;

    private const MALFORMED = 'The search result entry is malformed.';

    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): SearchResultEntry {
        $dn = self::stringOf(
            $type->getChild(0),
            self::MALFORMED,
        );

        $attributes = [];
        foreach ($type->getChild(1)?->getChildren() ?? [] as $partialAttribute) {
            $attributes[] = $this->attribute($partialAttribute);
        }

        return new SearchResultEntry(Entry::raw(
            new Dn($dn),
            $attributes,
        ));
    }

    /**
     * @param AbstractType<mixed> $partialAttribute
     * @throws ProtocolException
     */
    private function attribute(AbstractType $partialAttribute): Attribute
    {
        $values = [];
        $attrValues = $partialAttribute->getChild(1);
        if ($attrValues instanceof SetType || $attrValues instanceof SequenceType) {
            foreach ($attrValues->getChildren() as $attrValue) {
                $values[] = self::stringOf(
                    $attrValue,
                    self::MALFORMED,
                );
            }
        }

        return Attribute::fromArray(
            self::stringOf(
                $partialAttribute->getChild(0),
                self::MALFORMED,
            ),
            $values,
        );
    }
}
