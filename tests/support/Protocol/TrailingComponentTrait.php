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

/**
 * Appends a trailing component a later protocol extension might add, which RFC 4511 4 has a decoder ignore.
 */
trait TrailingComponentTrait
{
    /**
     * @template T of AbstractType<mixed>
     * @param T $type
     * @return T
     */
    private static function withTrailingComponent(AbstractType $type): AbstractType
    {
        return $type->addChild(Asn1::context(
            30,
            Asn1::octetString('extension'),
        ));
    }
}
