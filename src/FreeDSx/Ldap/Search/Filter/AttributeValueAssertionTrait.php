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
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Entry\Attribute;

/**
 * Common methods for filters using attribute value assertions.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait AttributeValueAssertionTrait
{
    use FilterAttributeTrait;

    private string $value;

    public function __construct(
        string $attribute,
        string $value,
    ) {
        $this->attribute = $attribute;
        $this->value = $value;
    }

    /**
     * @api
     */
    public function setValue(string $value): static
    {
        $this->value = $value;

        return $this;
    }

    public function getValue(): string
    {
        return $this->value;
    }

    public function toAsn1(): SequenceType
    {
        return Asn1::context(
            tagNumber: self::CHOICE_TAG,
            type: Asn1::sequence(
                Asn1::octetString($this->attribute),
                Asn1::octetString($this->value),
            ),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toString(): string
    {
        return self::PAREN_LEFT
            . $this->attributeToString()
            . self::FILTER_TYPE
            . Attribute::escape($this->value)
            . self::PAREN_RIGHT;
    }
}
