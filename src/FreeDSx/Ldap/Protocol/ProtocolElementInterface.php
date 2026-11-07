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

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Type\AbstractType;

/**
 * An object that encodes itself as ASN.1.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ProtocolElementInterface
{
    /**
     * Returns the Asn1 representation of an object that can be used by an encoder.
     *
     * @return AbstractType<mixed>
     */
    public function toAsn1(): AbstractType;
}
