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

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\InvalidArgumentException as Asn1InvalidArgumentException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

/**
 * Decodes one type of extended request from the value it carries.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
abstract readonly class ExtendedRequestValueDecoder
{
    /**
     * @throws ProtocolException
     * @throws EncoderException
     */
    abstract public function decode(
        ?string $value,
        DecodeContext $context,
    ): ExtendedRequest;

    /**
     * @return AbstractType<mixed>|null
     * @throws ProtocolException when the value is present but cannot be decoded.
     */
    protected function decodeValue(
        ?string $value,
        DecodeContext $context,
    ): ?AbstractType {
        if ($value === null) {
            return null;
        }

        try {
            return $context->decode($value);
        } catch (EncoderException|Asn1InvalidArgumentException $e) {
            // RFC 4511 4.1.1 answers a request that cannot be parsed with protocolError.
            throw new ProtocolException(
                ExtendedRequestDecoder::MALFORMED,
                0,
                $e,
            );
        }
    }
}
