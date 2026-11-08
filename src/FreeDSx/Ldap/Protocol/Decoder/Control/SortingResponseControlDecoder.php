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
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Sorting\SortingResponseControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

/**
 * Decodes a server side sorting response control (RFC 2891).
 *
 * @extends EncodedValueControlDecoder<SortingResponseControl>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SortingResponseControlDecoder extends EncodedValueControlDecoder
{
    protected function decodeValue(
        AbstractType $value,
        DecodeContext $context,
    ): SortingResponseControl {
        if (!$value instanceof SequenceType) {
            throw new ProtocolException('The server side sorting response is malformed.');
        }
        $result = $value->getChild(0);
        $attribute = $value->getChild(1);
        if (!$result instanceof EnumeratedType) {
            throw new ProtocolException('The server side sorting response is malformed.');
        }

        return new SortingResponseControl(
            $this->integerOf(
                $result,
                'server side sorting response result',
            ),
            $attribute === null ? null : $this->stringOf(
                $attribute,
                'server side sorting response attribute',
            ),
        );
    }
}
