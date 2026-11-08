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

namespace FreeDSx\Ldap\Protocol\Decoder\Request;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Asn1\Type\SetType;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

use function count;
use function sprintf;

/**
 * Decodes an add request (RFC 4511 4.7).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class AddRequestDecoder
{
    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): AddRequest {
        if (!($type instanceof SequenceType && count($type) >= 2)) {
            throw new ProtocolException('The add request is malformed.');
        }

        $dn = $type->getChild(0);
        $attrList = $type->getChild(1);
        if (!($dn instanceof OctetStringType && $attrList instanceof SequenceType)) {
            throw new ProtocolException('The add request is malformed.');
        }

        $entryDn = new Dn($dn->getValue());
        $attributes = [];
        foreach ($attrList->getChildren() as $attrListing) {
            $attributes[] = $this->attribute($attrListing);
        }

        return new AddRequest(new Entry(
            $entryDn,
            ...$attributes,
        ));
    }

    /**
     * @param AbstractType<mixed> $attrListing
     * @throws ProtocolException
     */
    private function attribute(AbstractType $attrListing): Attribute
    {
        if (!($attrListing instanceof SequenceType && count($attrListing->getChildren()) >= 2)) {
            throw new ProtocolException(sprintf(
                'Expected a sequence type, but received: %s',
                $attrListing::class,
            ));
        }

        $attrType = $attrListing->getChild(0);
        $vals = $attrListing->getChild(1);
        if (!($attrType instanceof OctetStringType && $vals instanceof SetType)) {
            throw new ProtocolException('The add request is malformed.');
        }

        // An Attribute constrains its values to SIZE(1..MAX), unlike the PartialAttribute a Modify carries.
        if (count($vals->getChildren()) === 0) {
            throw new ProtocolException(sprintf(
                'No values for attribute type "%s".',
                (string) $attrType->getValue(),
            ));
        }

        $attrValues = [];
        foreach ($vals->getChildren() as $val) {
            if (!$val instanceof OctetStringType) {
                throw new ProtocolException('The add request is malformed.');
            }
            $attrValues[] = $val->getValue();
        }

        return new Attribute(
            $attrType->getValue(),
            ...$attrValues,
        );
    }
}
