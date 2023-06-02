<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Search\Filter;

use ArrayIterator;
use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\SetType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\Factory\FilterFactory;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use Traversable;

/**
 * Methods needed to implement the filter container interface.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait FilterContainerTrait
{
    /**
     * @var FilterInterface[]
     */
    protected array $filters = [];

    /**
     * @param FilterInterface ...$filters
     */
    public function __construct(FilterInterface ...$filters)
    {
        $this->filters = $filters;
    }

    public function add(FilterInterface ...$filters): self
    {
        foreach ($filters as $filter) {
            $this->filters[] = $filter;
        }

        return $this;
    }

    public function has(FilterInterface $filter): bool
    {
        return in_array(
            $filter,
            $this->filters,
            true
        );
    }

    public function remove(FilterInterface ...$filters): self
    {
        foreach ($filters as $filter) {
            if (($i = array_search($filter, $this->filters, true)) !== false) {
                unset($this->filters[$i]);
            }
        }

        return $this;
    }

    public function set(FilterInterface ...$filters): self
    {
        $this->filters = $filters;

        return $this;
    }

    /**
     * @return FilterInterface[]
     */
    public function get(): array
    {
        return $this->filters;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        return Asn1::context(
            tagNumber: self::CHOICE_TAG,
            type: Asn1::setOf(...array_map(
                fn (FilterInterface $filter) => $filter->toAsn1(),
                $this->filters
            )),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toString(): string
    {
        return self::PAREN_LEFT
            . self::FILTER_OPERATOR
            . implode('', array_map(function (FilterInterface $filter) {
                return $filter->toString();
            }, $this->filters))
            . self::PAREN_RIGHT;
    }

    /**
     * @return Traversable<FilterInterface>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->filters);
    }

    /**
     * @inheritDoc
     * @psalm-return 0|positive-int
     */
    public function count(): int
    {
        return count($this->filters);
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * {@inheritDoc}
     * @throws EncoderException
     * @throws ProtocolException
     */
    public static function fromAsn1(AbstractType $type): self
    {
        if ($type instanceof IncompleteType) {
            $type = (new LdapEncoder())->complete(
                type: $type,
                tagType: AbstractType::TAG_TYPE_SET
            );
        }

        if (!$type instanceof SetType) {
            throw new ProtocolException('The filter is malformed');
        }

        $filters = [];
        foreach ($type->getChildren() as $child) {
            $filters[] = FilterFactory::get($child);
        }

        return new self(...$filters);
    }
}
