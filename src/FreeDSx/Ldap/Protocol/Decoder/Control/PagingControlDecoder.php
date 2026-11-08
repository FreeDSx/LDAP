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
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

/**
 * Decodes a paged results control (RFC 2696), sent by the client as a request and the server as a response.
 *
 * @extends EncodedValueControlDecoder<PagingControl>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class PagingControlDecoder extends EncodedValueControlDecoder
{
    protected function decodeValue(
        AbstractType $value,
        DecodeContext $context,
    ): PagingControl {
        if (!$value instanceof SequenceType) {
            throw new ProtocolException('A paged control value must be a sequence type with 2 children.');
        }
        $count = $value->getChild(0);
        $cookie = $value->getChild(1);
        if (!$count instanceof IntegerType) {
            throw new ProtocolException('A paged control value sequence 0 must be an integer type.');
        }
        if (!$cookie instanceof OctetStringType) {
            throw new ProtocolException('A paged control value sequence 1 must be an octet string type.');
        }

        return new PagingControl(
            $this->integerOf(
                $count,
                'paged control size',
            ),
            $cookie->getValue(),
        );
    }
}
