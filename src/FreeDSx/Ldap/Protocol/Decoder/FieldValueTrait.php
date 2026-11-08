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

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\EnumeratedType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Ldap\Exception\ProtocolException;

use function is_int;

/**
 * Reads the value of a received field, refusing a field of the wrong ASN.1 type with the message given.
 *
 * @internal
 */
trait FieldValueTrait
{
    /**
     * @param AbstractType<mixed>|null $type
     * @throws ProtocolException
     */
    private static function stringOf(
        ?AbstractType $type,
        string $malformed,
    ): string {
        if (!$type instanceof OctetStringType) {
            throw new ProtocolException($malformed);
        }

        return $type->getValue();
    }

    /**
     * Refuses an ENUMERATED wider than a native integer as well.
     *
     * @param AbstractType<mixed>|null $type
     * @throws ProtocolException
     */
    private static function enumeratedOf(
        ?AbstractType $type,
        string $malformed,
    ): int {
        $value = $type instanceof EnumeratedType
            ? $type->getValue()
            : null;
        if (!is_int($value)) {
            throw new ProtocolException($malformed);
        }

        return $value;
    }
}
