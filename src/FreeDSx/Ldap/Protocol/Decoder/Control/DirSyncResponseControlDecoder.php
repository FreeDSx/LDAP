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
use FreeDSx\Ldap\Control\Ad\DirSyncResponseControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

/**
 * Decodes an Active Directory DirSync response control (MS-ADTS 3.1.1.3.4.1.3).
 *
 * @extends EncodedValueControlDecoder<DirSyncResponseControl>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class DirSyncResponseControlDecoder extends EncodedValueControlDecoder
{
    protected function decodeValue(
        AbstractType $value,
        DecodeContext $context,
    ): DirSyncResponseControl {
        if (!$value instanceof SequenceType) {
            throw new ProtocolException('A DirSyncResponse control value must be a sequence type with 3 children.');
        }
        $more = $value->getChild(0);
        $unused = $value->getChild(1);
        $cookie = $value->getChild(2);
        if (!$more instanceof IntegerType) {
            throw new ProtocolException('A DirSyncResponse control value sequence 0 must be an integer type.');
        }
        if (!$unused instanceof IntegerType) {
            throw new ProtocolException('A DirSyncResponse control value sequence 1 must be an integer type.');
        }
        if (!$cookie instanceof OctetStringType) {
            throw new ProtocolException('A DirSyncResponse control value sequence 2 must be an octet string type.');
        }

        return new DirSyncResponseControl(
            $this->integerOf(
                $more,
                'DirSyncResponse more results value',
            ),
            $this->integerOf(
                $unused,
                'DirSyncResponse unused value',
            ),
            $cookie->getValue(),
        );
    }
}
