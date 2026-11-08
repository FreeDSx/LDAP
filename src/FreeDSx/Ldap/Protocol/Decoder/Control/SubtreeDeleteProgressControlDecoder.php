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
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\SubtreeDeleteProgressControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

use function is_int;

/**
 * Decodes the progress control a server returns on a subtree delete that stopped at its limit.
 *
 * @extends EncodedValueControlDecoder<SubtreeDeleteProgressControl>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SubtreeDeleteProgressControlDecoder extends EncodedValueControlDecoder
{
    private const MALFORMED = 'The subtree delete progress control is malformed.';

    protected function decodeValue(
        AbstractType $value,
        DecodeContext $context,
    ): SubtreeDeleteProgressControl {
        if (!$value instanceof SequenceType) {
            throw new ProtocolException(self::MALFORMED);
        }
        $deleted = $value->getChild(0);
        if (!$deleted instanceof IntegerType) {
            throw new ProtocolException(self::MALFORMED);
        }

        return new SubtreeDeleteProgressControl(
            $this->integerOf(
                $deleted,
                'subtree delete progress deleted count',
            ),
            $this->remaining(
                $value->getChild(1),
                $context,
            ),
        );
    }

    /**
     * @param AbstractType<mixed>|null $remaining
     * @throws ProtocolException
     * @throws EncoderException
     */
    private function remaining(
        ?AbstractType $remaining,
        DecodeContext $context,
    ): ?int {
        if ($remaining === null) {
            return null;
        }
        if (!$remaining instanceof IncompleteType || $remaining->getTagNumber() !== 0) {
            throw new ProtocolException(self::MALFORMED);
        }

        $value = $context->complete(
            $remaining,
            AbstractType::TAG_TYPE_INTEGER,
        )->getValue();

        return is_int($value)
            ? $value
            : null;
    }
}
