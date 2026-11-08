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
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

use function is_string;

/**
 * Decodes a password modify response (RFC 3062) and any password the server generated.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class PasswordModifyResponseDecoder implements ExtendedResponseValueDecoderInterface
{
    /**
     * @throws ProtocolException
     * @throws EncoderException
     * @throws PartialPduException
     */
    public function decode(
        ExtendedResponse $response,
        DecodeContext $context,
    ): PasswordModifyResponse {
        return new PasswordModifyResponse(
            $response,
            $this->generatedPassword(
                $response->getValue(),
                $context,
            ),
        );
    }

    /**
     * @throws ProtocolException
     * @throws EncoderException
     * @throws PartialPduException
     */
    private function generatedPassword(
        ?string $value,
        DecodeContext $context,
    ): ?string {
        if ($value === null) {
            return null;
        }
        $pwdResponse = $context->decode($value);
        if (!$pwdResponse instanceof SequenceType) {
            return null;
        }

        $generatedPassword = null;
        foreach ($pwdResponse->getChildren() as $child) {
            if ($child->getTagNumber() !== 0) {
                continue;
            }
            // A context tagged field is left as its raw bytes; any other form of tag 0 holds no password.
            $password = $child->getValue();
            $generatedPassword = is_string($password)
                ? $password
                : null;
        }

        return $generatedPassword;
    }
}
