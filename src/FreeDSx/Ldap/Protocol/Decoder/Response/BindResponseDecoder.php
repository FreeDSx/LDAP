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
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\OperationDecoderInterface;

use function is_string;

/**
 * Decodes a bind response (RFC 4511 4.2.2) and any SASL credentials it carries.
 *
 * @implements OperationDecoderInterface<BindResponse>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class BindResponseDecoder implements OperationDecoderInterface
{
    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): BindResponse {
        $fields = LdapResultFields::of(
            $type,
            $context,
        );

        return new BindResponse(
            $fields->result(),
            $this->saslCredentials($type),
        );
    }

    /**
     * @param AbstractType<mixed> $type
     */
    private function saslCredentials(AbstractType $type): ?string
    {
        foreach ($type->getChildren() as $child) {
            if ($child->getTagNumber() !== 7 || $child->getTagClass() !== AbstractType::TAG_CLASS_CONTEXT_SPECIFIC) {
                continue;
            }
            // A context tagged field is left as its raw bytes.
            $credentials = $child->getValue();

            return is_string($credentials)
                ? $credentials
                : null;
        }

        return null;
    }
}
