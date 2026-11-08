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
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\BooleanType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

use function count;
use function is_string;

/**
 * Decodes a modify DN request (RFC 4511 4.9).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ModifyDnRequestDecoder implements RequestDecoderInterface
{
    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): ModifyDnRequest {
        if (!($type instanceof SequenceType && count($type) >= 3)) {
            throw new ProtocolException('The modify dn request is malformed');
        }
        $entry = $type->getChild(0);
        $newRdn = $type->getChild(1);
        $deleteOldRdn = $type->getChild(2);

        if (
            !($entry instanceof OctetStringType
            && $newRdn instanceof OctetStringType
            && $deleteOldRdn instanceof BooleanType)
        ) {
            throw new ProtocolException('The modify dn request is malformed');
        }

        return new ModifyDnRequest(
            $entry->getValue(),
            $newRdn->getValue(),
            $deleteOldRdn->getValue(),
            $this->newSuperior(
                $type->getChild(3),
                $context,
            ),
        );
    }

    /**
     * @param AbstractType<mixed>|null $component
     * @throws EncoderException
     * @throws ProtocolException
     */
    private function newSuperior(
        ?AbstractType $component,
        DecodeContext $context,
    ): ?string {
        if (!$this->isNewSuperior($component)) {
            return null;
        }
        $newSuperior = ($component instanceof IncompleteType)
            ? $context->complete(
                $component,
                AbstractType::TAG_TYPE_OCTET_STRING,
            )
            : $component;

        $value = $newSuperior->getValue();
        if (!is_string($value)) {
            throw new ProtocolException('The modify dn request is malformed');
        }

        return $value;
    }

    /**
     * RFC 4511 4: a trailing component with any other tag is an extension to ignore, not a newSuperior.
     *
     * @param AbstractType<mixed>|null $component
     * @phpstan-assert-if-true AbstractType<mixed> $component
     */
    private function isNewSuperior(?AbstractType $component): bool
    {
        return $component !== null
            && $component->getTagClass() === AbstractType::TAG_CLASS_CONTEXT_SPECIFIC
            && $component->getTagNumber() === 0;
    }
}
