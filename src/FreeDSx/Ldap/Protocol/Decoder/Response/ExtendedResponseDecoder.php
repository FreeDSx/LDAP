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
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\OperationDecoderInterface;

use function is_string;

/**
 * Decodes an extended response (RFC 4511 4.12) into its generic form, keeping the name and value it carries.
 *
 * @implements OperationDecoderInterface<ExtendedResponse>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ExtendedResponseDecoder implements OperationDecoderInterface
{
    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): ExtendedResponse {
        $result = LdapResultFields::of(
            $type,
            $context,
        )->result();

        return new ExtendedResponse(
            $result,
            ...$this->nameAndValue($type),
        );
    }

    /**
     * @param AbstractType<mixed> $type
     * @return array{0: ?string, 1: ?string}
     */
    private function nameAndValue(AbstractType $type): array
    {
        $info = [0 => null, 1 => null];

        foreach ($type->getChildren() as $child) {
            $tagNumber = $child->getTagNumber();
            if ($tagNumber !== 10 && $tagNumber !== 11) {
                continue;
            }
            $value = $child->getValue();
            if ($value !== null && !is_string($value)) {
                continue;
            }
            $info[$tagNumber === 10 ? 0 : 1] = $value;
        }

        return $info;
    }
}
