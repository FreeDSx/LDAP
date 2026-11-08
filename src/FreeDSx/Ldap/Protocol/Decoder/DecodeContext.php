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
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\LdapEncoder;

/**
 * Decodes the nested parts of one received message, all through the same encoder.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class DecodeContext
{
    public function __construct(private LdapEncoder $encoder) {}

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
     * @throws ProtocolException when the bytes are empty.
     */
    public function decode(
        string $bytes,
        array $tagMap = [],
    ): AbstractType {
        // An empty value is malformed like any other, so it is answered rather than ending the session.
        if ($bytes === '') {
            throw new ProtocolException('The data to decode cannot be empty.');
        }

        return $this->encoder->decode(
            $bytes,
            $tagMap,
        );
    }
}
