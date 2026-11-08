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

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Protocol\LdapEncoder;

/**
 * Turns a built ASN.1 type into the form it arrives in, with its context tagged parts left undecoded.
 */
trait ReceivedAsn1Trait
{
    /**
     * @param AbstractType<mixed> $type
     * @return AbstractType<mixed>
     */
    private static function received(AbstractType $type): AbstractType
    {
        $encoder = new LdapEncoder();

        return $encoder->decode($encoder->encode($type));
    }
}
