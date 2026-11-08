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

namespace FreeDSx\Ldap\Protocol\Decoder\Control;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\EnumeratedType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Vlv\VlvResponseControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

/**
 * Decodes a virtual list view response control (draft-ietf-ldapext-ldapv3-vlv-09).
 *
 * @extends EncodedValueControlDecoder<VlvResponseControl>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class VlvResponseControlDecoder extends EncodedValueControlDecoder
{
    private const MALFORMED = 'The VLV response value contains an unexpected ASN1 type.';

    protected function decodeValue(
        AbstractType $value,
        DecodeContext $context,
    ): VlvResponseControl {
        if (!$value instanceof SequenceType) {
            throw new ProtocolException(self::MALFORMED);
        }
        $offset = $value->getChild(0);
        $count = $value->getChild(1);
        $result = $value->getChild(2);
        $contextId = $value->getChild(3);

        if (!$offset instanceof IntegerType) {
            throw new ProtocolException(self::MALFORMED);
        }
        if (!$count instanceof IntegerType) {
            throw new ProtocolException(self::MALFORMED);
        }
        if (!$result instanceof EnumeratedType) {
            throw new ProtocolException(self::MALFORMED);
        }
        if ($contextId !== null && !$contextId instanceof OctetStringType) {
            throw new ProtocolException(self::MALFORMED);
        }

        return new VlvResponseControl(
            $this->integerOf(
                $offset,
                'VLV response target position',
            ),
            $this->integerOf(
                $count,
                'VLV response content count',
            ),
            $this->integerOf(
                $result,
                'VLV response result',
            ),
            $contextId?->getValue(),
        );
    }
}
