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

namespace FreeDSx\Ldap\Protocol\Decoder\Response;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

use function sprintf;

/**
 * Decodes the typed form of an extended response from its generic form, by the OID of the request it answers.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class TypedExtendedResponseDecoder
{
    /**
     * @param array<string, ExtendedResponseValueDecoderInterface> $decoders keyed by the OID of the request answered.
     */
    public function __construct(private array $decoders) {}

    public function has(string $requestOid): bool
    {
        return isset($this->decoders[$requestOid]);
    }

    /**
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function decode(
        ExtendedResponse $response,
        string $requestOid,
        DecodeContext $context,
    ): ExtendedResponse {
        $decoder = $this->decoders[$requestOid] ?? throw new ProtocolException(sprintf(
            'There is no extended response mapped for %s.',
            $requestOid,
        ));

        return $decoder->decode(
            $response,
            $context,
        );
    }
}
