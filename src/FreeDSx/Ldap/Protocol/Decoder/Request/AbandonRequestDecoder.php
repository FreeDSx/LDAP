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
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

use function is_int;

/**
 * Decodes an abandon request (RFC 4511 4.11).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class AbandonRequestDecoder
{
    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): AbandonRequest {
        if (!$type instanceof IntegerType) {
            throw new ProtocolException('The abandon request is malformed');
        }

        $messageId = $type->getValue();
        if (!is_int($messageId)) {
            throw new ProtocolException('The abandon request message ID is not an integer.');
        }

        return new AbandonRequest($messageId);
    }
}
