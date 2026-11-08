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
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response\IntermediateResponse;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

use function is_string;

/**
 * Decodes an intermediate response (RFC 4511 4.13), handing a sync info message to its own decoder.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class IntermediateResponseDecoder implements ResponseDecoderInterface
{
    public function __construct(private SyncInfoDecoder $syncInfo) {}

    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     * @throws EncoderException
     * @throws PartialPduException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): IntermediateResponse {
        if (!$type instanceof SequenceType) {
            throw new ProtocolException('The intermediate response is malformed');
        }

        [$name, $value] = $this->nameAndValue($type);
        if ($name === IntermediateResponse::OID_SYNC_INFO) {
            return $this->syncInfo->decode(
                $type,
                $context,
            );
        }

        return new IntermediateResponse(
            $name,
            $value,
        );
    }

    /**
     * @return array{0: ?string, 1: ?string}
     */
    private function nameAndValue(SequenceType $type): array
    {
        $name = null;
        $value = null;
        foreach ($type->getChildren() as $child) {
            if ($child->getTagClass() !== AbstractType::TAG_CLASS_CONTEXT_SPECIFIC) {
                continue;
            }
            $childValue = $child->getValue();
            if ($childValue !== null && !is_string($childValue)) {
                continue;
            }
            if ($child->getTagNumber() === 0) {
                $name = $childValue;
            } elseif ($child->getTagNumber() === 1) {
                $value = $childValue;
            }
        }

        return [$name, $value];
    }
}
