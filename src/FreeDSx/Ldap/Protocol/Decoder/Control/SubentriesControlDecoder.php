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
use FreeDSx\Asn1\Type\BooleanType;
use FreeDSx\Ldap\Control\SubentriesControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

/**
 * Decodes a subentries control (RFC 3672 3).
 *
 * @extends EncodedValueControlDecoder<SubentriesControl>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SubentriesControlDecoder extends EncodedValueControlDecoder
{
    protected function decodeValue(
        AbstractType $value,
        DecodeContext $context,
    ): SubentriesControl {
        if (!$value instanceof BooleanType) {
            throw new ProtocolException('Expected a boolean type for a subentries control value.');
        }

        return new SubentriesControl($value->getValue());
    }
}
