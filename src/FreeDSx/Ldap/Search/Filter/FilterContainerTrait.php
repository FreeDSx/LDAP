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

use ArrayIterator;
use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\SetOfType;
use Traversable;

/**
 * Methods needed to implement the filter container interface.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait FilterContainerTrait
{
    /**
     * @var FilterInterface[]
     */
    protected array $filters = [];

    public function __construct(FilterInterface ...$filters)
    {
        $this->filters = $filters;
    }

    public function __toString(): string
    {
        return $this->toString();
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
            true,
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

    public function toAsn1(): SetOfType
    {
        $filters = [];
        foreach ($this->filters as $filter) {
            $filters[] = $filter->toAsn1();
        }

        return Asn1::context(
            tagNumber: self::CHOICE_TAG,
            type: SetOfType::fromChildren($filters),
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
}
