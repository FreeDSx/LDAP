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

namespace FreeDSx\Ldap\Search\Filter;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\OctetStringType;
use Stringable;

/**
 * Checks for the presence of an attribute (ie. whether or not it contains a value). RFC 4511, 4.5.1.7.5
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PresentFilter implements FilterInterface, FilterAttributeInterface, Stringable
{
    use FilterAttributeTrait;

    protected const APP_TAG = 7;

    public function __construct(string $attribute)
    {
        $this->attribute = $attribute;
    }

    public function toAsn1(): OctetStringType
    {
        return Asn1::context(
            tagNumber: self::APP_TAG,
            type: Asn1::octetString($this->attribute),
        );
    }

    public function toString(): string
    {
        return self::PAREN_LEFT
            . $this->attributeToString()
            . self::FILTER_EQUAL
            . '*'
            . self::PAREN_RIGHT;
    }
}
