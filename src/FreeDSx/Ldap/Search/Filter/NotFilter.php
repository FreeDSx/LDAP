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
use Stringable;

/**
 * Represents the negation of a filter. RFC 4511, 4.5.1
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class NotFilter implements FilterInterface, Stringable
{
    protected const CHOICE_TAG = 2;

    private FilterInterface $filter;

    public function __construct(FilterInterface $filter)
    {
        $this->filter = $filter;
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    public function get(): FilterInterface
    {
        return $this->filter;
    }

    public function set(FilterInterface $filter): self
    {
        $this->filter = $filter;

        return $this;
    }

    public function toAsn1(): SequenceType
    {
        return Asn1::context(
            tagNumber: self::CHOICE_TAG,
            type: Asn1::sequence($this->filter->toAsn1()),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toString(): string
    {
        return self::PAREN_LEFT
            . self::OPERATOR_NOT
            . $this->filter->toString()
            . self::PAREN_RIGHT;
    }
}
