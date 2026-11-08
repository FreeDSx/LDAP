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

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

/**
 * Decodes a password policy response control (draft-behera-ldap-password-policy-10).
 *
 * @extends EncodedValueControlDecoder<PwdPolicyResponseControl>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class PwdPolicyResponseControlDecoder extends EncodedValueControlDecoder
{
    private const WARNING_TAGS = [
        AbstractType::TAG_CLASS_CONTEXT_SPECIFIC => [
            0 => AbstractType::TAG_TYPE_INTEGER,
            1 => AbstractType::TAG_TYPE_INTEGER,
        ],
    ];

    protected function decodeValue(
        AbstractType $value,
        DecodeContext $context,
    ): PwdPolicyResponseControl {
        $warnings = [];
        $error = null;

        foreach ($value->getChildren() as $child) {
            if (!$child instanceof IncompleteType) {
                throw new ProtocolException('The ASN1 structure for the pwdPolicy control is malformed.');
            }
            if ($child->getTagNumber() === 0) {
                $warnings = $this->warning($child, $context) + $warnings;
            } elseif ($child->getTagNumber() === 1) {
                $error = $this->integerOf(
                    $context->complete(
                        $child,
                        AbstractType::TAG_TYPE_ENUMERATED,
                    ),
                    'pwdPolicy control error',
                );
            }
        }

        return new PwdPolicyResponseControl(
            $warnings[0] ?? null,
            $warnings[1] ?? null,
            $error,
        );
    }

    /**
     * Gets the first warning keyed by its tag, 0 for the time before expiration and 1 for the grace logins remaining.
     *
     * @return array<int, int>
     * @throws ProtocolException
     * @throws EncoderException
     */
    private function warning(
        IncompleteType $child,
        DecodeContext $context,
    ): array {
        $warnings = $context->complete(
            $child,
            AbstractType::TAG_TYPE_SEQUENCE,
            self::WARNING_TAGS,
        );

        foreach ($warnings->getChildren() as $warning) {
            if ($warning->getTagNumber() === 0) {
                return [0 => $this->integerOf(
                    $warning,
                    'pwdPolicy control time before expiration',
                )];
            }
            if ($warning->getTagNumber() === 1) {
                return [1 => $this->integerOf(
                    $warning,
                    'pwdPolicy control grace authentications remaining',
                )];
            }
        }

        return [];
    }
}
