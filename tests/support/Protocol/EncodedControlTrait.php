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

namespace Tests\Support\FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Protocol\LdapEncoder;

/**
 * Builds a received control whose value is the BER encoding of the given type.
 */
trait EncodedControlTrait
{
    /**
     * @param AbstractType<mixed> $value
     */
    private static function encodedControl(
        string $oid,
        AbstractType $value,
        bool $criticality = false,
    ): SequenceType {
        return Asn1::sequence(
            Asn1::octetString($oid),
            Asn1::boolean($criticality),
            Asn1::octetString((new LdapEncoder())->encode($value)),
        );
    }
}
