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

namespace FreeDSx\Ldap\Protocol\Decoder;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Protocol\LdapEncoder;

/**
 * Decodes the nested parts of one received message, all through the same encoder.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DecodeContext
{
    public function __construct(private readonly LdapEncoder $encoder) {}

    /**
     * @param array<int, array<int, int>> $tagMap
     * @return AbstractType<mixed>
     * @throws EncoderException
     */
    public function complete(
        IncompleteType $type,
        int $tagType,
        array $tagMap = [],
    ): AbstractType {
        return $this->encoder->complete(
            $type,
            $tagType,
            $tagMap,
        );
    }

    /**
     * @param array<int, array<int, int>> $tagMap
     * @return AbstractType<mixed>
     * @throws EncoderException
     * @throws PartialPduException
     */
    public function decode(
        string $bytes,
        array $tagMap = [],
    ): AbstractType {
        return $this->encoder->decode(
            $bytes,
            $tagMap,
        );
    }
}
