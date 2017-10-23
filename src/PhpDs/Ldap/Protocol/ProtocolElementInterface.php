<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Protocol;

use PhpDs\Ldap\Asn1\Type\AbstractType;

/**
 * Methods needed to transform an object to ASN1 representation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ProtocolElementInterface
{
    /**
     * Returns the Asn1 representation of an object that can be used by an encoder.
     *
     * @return AbstractType
     */
    public function toAsn1() : AbstractType;

    /**
     * @param AbstractType $type
     * @return mixed
     */
    public static function fromAsn1(AbstractType $type);
}
