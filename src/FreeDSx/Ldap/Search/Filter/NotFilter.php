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
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\Factory\FilterFactory;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use Stringable;

/**
 * Represents the negation of a filter. RFC 4511, 4.5.1
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

    public function get(): FilterInterface
    {
        return $this->filter;
    }

    public function set(FilterInterface $filter): self
    {
        $this->filter = $filter;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
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

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * {@inheritDoc}
     * @throws ProtocolException
     * @throws EncoderException
     * @throws RuntimeException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        $type = $type instanceof IncompleteType ? (new LdapEncoder())->complete($type, AbstractType::TAG_TYPE_SEQUENCE) : $type;
        if (!($type instanceof SequenceType && count($type) === 1)) {
            throw new ProtocolException('The not filter is malformed');
        }
        $child = $type->getChild(0);
        if ($child === null) {
            throw new ProtocolException('The "not" filter is malformed.');
        }

        return new static(FilterFactory::get($child));
    }
}
