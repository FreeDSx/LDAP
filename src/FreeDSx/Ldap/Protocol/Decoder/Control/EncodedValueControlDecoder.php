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
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

use function is_int;
use function is_string;
use function sprintf;

/**
 * Decodes a control whose value is itself BER encoded.
 *
 * @template T of Control
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
abstract readonly class EncodedValueControlDecoder
{
    /**
     * @return T
     * @throws ProtocolException
     * @throws EncoderException
     * @throws PartialPduException
     */
    public function decode(
        SequenceType $control,
        DecodeContext $context,
    ): Control {
        $fields = ControlFields::of($control);
        if ($fields->value === null) {
            throw new ProtocolException('The received control is malformed. Unable to get the encoded value.');
        }

        return $fields->applyTo($this->decodeValue(
            $context->decode($fields->value),
            $context,
        ));
    }

    /**
     * @param AbstractType<mixed> $value
     * @return T
     * @throws ProtocolException
     * @throws EncoderException
     */
    abstract protected function decodeValue(
        AbstractType $value,
        DecodeContext $context,
    ): Control;

    /**
     * Gets a decoded integer field, refusing one wider than a native integer.
     *
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     */
    protected function integerOf(
        AbstractType $type,
        string $field,
    ): int {
        $value = $type->getValue();
        if (!is_int($value)) {
            throw new ProtocolException(sprintf(
                'The %s is not an integer.',
                $field,
            ));
        }

        return $value;
    }

    /**
     * Gets a decoded string field, refusing a value of any other type.
     *
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     */
    protected function stringOf(
        AbstractType $type,
        string $field,
    ): string {
        $value = $type->getValue();
        if (!is_string($value)) {
            throw new ProtocolException(sprintf(
                'The %s is not a string.',
                $field,
            ));
        }

        return $value;
    }
}
