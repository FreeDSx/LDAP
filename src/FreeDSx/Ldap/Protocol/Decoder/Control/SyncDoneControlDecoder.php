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
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

use function count;

/**
 * Decodes a sync done control (RFC 4533 2.4).
 *
 * @extends EncodedValueControlDecoder<SyncDoneControl>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SyncDoneControlDecoder extends EncodedValueControlDecoder
{
    protected function decodeValue(
        AbstractType $value,
        DecodeContext $context,
    ): SyncDoneControl {
        if (!$value instanceof SequenceType || count($value->getChildren()) > 2) {
            throw new ProtocolException(
                'Expected a sequence type with 2 or less values for a sync done control value.',
            );
        }

        $cookie = null;
        $refreshDeletes = false;
        foreach ($value->getChildren() as $child) {
            if ($child instanceof OctetStringType) {
                $cookie = $child->getValue();
            } elseif ($child instanceof BooleanType) {
                $refreshDeletes = $child->getValue();
            }
        }

        return new SyncDoneControl(
            $cookie,
            $refreshDeletes,
        );
    }
}
