<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Asn1\Encoder;

use PhpDs\Ldap\Asn1\Type\AbstractType;
use PhpDs\Ldap\Asn1\Type\IncompleteType;

/**
 * The ASN1 encoder interface.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface EncoderInterface
{
    /**
     * Encode a type to its binary form.
     *
     * @param AbstractType $type
     * @return string
     */
    public function encode(AbstractType $type) : string;

    /**
     * Decodes (completes) an incomplete type to a specific universal tag type object.
     *
     * @param IncompleteType $type
     * @param int $tagType
     * @param array $tagMap
     * @return mixed
     */
    public function complete(IncompleteType $type, int $tagType, array $tagMap = []) : AbstractType;

    /**
     * Decode binary data to its ASN1 object representation.
     *
     * @param string $binary
     * @param array $tagMap
     * @return AbstractType
     */
    public function decode($binary, array $tagMap = []) : AbstractType;
}
