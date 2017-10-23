<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Operation\Request;

use PhpDs\Ldap\Asn1\Asn1;
use PhpDs\Ldap\Asn1\Type\AbstractType;

/**
 * A request to unbind. RFC 4511, 4.3
 *
 * UnbindRequest ::= [APPLICATION 2] NULL
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class UnbindRequest implements RequestInterface
{
    protected const APP_TAG = 2;

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        return new self();
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        return Asn1::application(self::APP_TAG, Asn1::null());
    }
}
