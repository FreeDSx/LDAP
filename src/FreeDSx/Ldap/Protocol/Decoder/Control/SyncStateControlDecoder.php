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
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

use function count;

/**
 * Decodes a sync state control (RFC 4533 2.3).
 *
 * @extends EncodedValueControlDecoder<SyncStateControl>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SyncStateControlDecoder extends EncodedValueControlDecoder
{
    protected function decodeValue(
        AbstractType $value,
        DecodeContext $context,
    ): SyncStateControl {
        $count = count($value->getChildren());
        if (!($value instanceof SequenceType && ($count === 3 || $count === 2))) {
            throw new ProtocolException('Expected a sequence type with 2 or 3 values for a sync state control value.');
        }
        $state = $value->getChild(0);
        if (!$state instanceof EnumeratedType) {
            throw new ProtocolException('Expected an enumerated type for the state control value.');
        }
        $entryUuid = $value->getChild(1);
        if (!$entryUuid instanceof OctetStringType) {
            throw new ProtocolException('Expected an octet string type for the state control value.');
        }
        $cookie = $value->getChild(2);
        if ($cookie !== null && !$cookie instanceof OctetStringType) {
            throw new ProtocolException('Expected an octet string type for the sync state cookie value.');
        }

        return new SyncStateControl(
            $this->integerOf(
                $state,
                'sync state control state',
            ),
            $entryUuid->getValue(),
            $cookie?->getValue(),
        );
    }
}
