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

use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

/**
 * Decodes each control one side receives, through the decoder for its OID or as a generic control otherwise.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ControlDecoder implements ControlDecoderInterface
{
    /**
     * @param array<string, ControlDecoderInterface> $decoders the decoder of each typed control, keyed by its OID.
     */
    public function __construct(private array $decoders) {}

    public function decode(
        SequenceType $control,
        DecodeContext $context,
    ): Control {
        $fields = ControlFields::of($control);
        $decoder = $this->decoders[$fields->oid] ?? null;

        if ($decoder !== null) {
            return $decoder->decode(
                $control,
                $context,
            );
        }

        return new Control(
            $fields->oid,
            $fields->criticality,
            $fields->value,
        );
    }
}
