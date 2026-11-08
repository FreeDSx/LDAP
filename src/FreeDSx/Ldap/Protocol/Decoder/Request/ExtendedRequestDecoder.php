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
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\OperationDecoderInterface;

use function count;
use function is_string;

/**
 * Decodes an extended request (RFC 4511 4.12), into its own type when one is decoded from its value.
 *
 * @implements OperationDecoderInterface<ExtendedRequest>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ExtendedRequestDecoder implements OperationDecoderInterface
{
    public const MALFORMED = 'The extended request is malformed.';

    /**
     * @param array<string, ExtendedRequestValueDecoder> $values the decoder of each request type, keyed by its OID.
     */
    public function __construct(private array $values) {}

    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): ExtendedRequest {
        [$oid, $value] = $this->nameAndValue($type);
        $decoder = $this->values[$oid] ?? null;

        if ($decoder === null) {
            return new ExtendedRequest(
                $oid,
                $value,
            );
        }

        return $decoder->decode(
            $value,
            $context,
        );
    }

    /**
     * @param AbstractType<mixed> $type
     * @return array{0: string, 1: null|string}
     * @throws ProtocolException
     */
    private function nameAndValue(AbstractType $type): array
    {
        if (!($type instanceof SequenceType && count($type) >= 1)) {
            throw new ProtocolException(self::MALFORMED);
        }
        $oid = null;
        $value = null;

        foreach ($type->getChildren() as $child) {
            if ($child->getTagClass() !== AbstractType::TAG_CLASS_CONTEXT_SPECIFIC) {
                continue;
            }
            if ($child->getTagNumber() === 0) {
                $oid = $child;
            } elseif ($child->getTagNumber() === 1) {
                $value = $child;
            }
        }
        if ($oid === null) {
            throw new ProtocolException(self::MALFORMED);
        }

        $oidValue = $oid->getValue();
        $rawValue = $value?->getValue();
        if (!is_string($oidValue) || ($rawValue !== null && !is_string($rawValue))) {
            throw new ProtocolException(self::MALFORMED);
        }

        return [
            $oidValue,
            $rawValue,
        ];
    }
}
