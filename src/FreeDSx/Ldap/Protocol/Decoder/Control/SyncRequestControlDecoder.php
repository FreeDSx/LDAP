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
use FreeDSx\Asn1\Type\EnumeratedType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

use function count;

/**
 * Decodes a sync request control (RFC 4533 2.2).
 *
 * @extends EncodedValueControlDecoder<SyncRequestControl>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SyncRequestControlDecoder extends EncodedValueControlDecoder
{
    protected function decodeValue(
        AbstractType $value,
        DecodeContext $context,
    ): SyncRequestControl {
        if (!$value instanceof SequenceType || count($value->getChildren()) > 3) {
            throw new ProtocolException(
                'Expected a sequence type with 2 or less values for a sync request control value.',
            );
        }

        $cookie = null;
        $mode = null;
        $reloadHint = false;
        foreach ($value->getChildren() as $child) {
            if ($child instanceof OctetStringType) {
                $cookie = $child->getValue();
            } elseif ($child instanceof BooleanType) {
                $reloadHint = $child->getValue();
            } elseif ($child instanceof EnumeratedType) {
                $mode = $child;
            }
        }

        if ($mode === null) {
            throw new ProtocolException('Expected an enumerated type for the sync request mode.');
        }

        return new SyncRequestControl(
            $this->integerOf(
                $mode,
                'sync request control mode',
            ),
            $cookie,
            $reloadHint,
        );
    }
}
