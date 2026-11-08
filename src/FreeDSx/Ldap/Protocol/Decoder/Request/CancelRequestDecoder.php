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

use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

use function is_int;

/**
 * Decodes a cancel request (RFC 3909) from its value.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class CancelRequestDecoder extends ExtendedRequestValueDecoder
{
    public function decode(
        ?string $value,
        DecodeContext $context,
    ): CancelRequest {
        $decoded = $this->decodeValue(
            $value,
            $context,
        );
        if (!($decoded instanceof SequenceType && $decoded->getChild(0) instanceof IntegerType)) {
            throw new ProtocolException('The cancel request value is malformed.');
        }

        $messageId = $decoded->getChild(0)->getValue();
        if (!is_int($messageId)) {
            throw new ProtocolException('The cancel request message ID is not an integer.');
        }

        return new CancelRequest($messageId);
    }
}
