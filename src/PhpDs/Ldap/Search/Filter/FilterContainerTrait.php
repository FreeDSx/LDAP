<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Search\Filter;

use PhpDs\Ldap\Asn1\Asn1;
use PhpDs\Ldap\Asn1\Type\AbstractType;

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
    protected $filters;

    /**
     * @param FilterInterface[] ...$filters
     */
    public function __construct(FilterInterface ...$filters)
    {
        $this->filters = $filters;
    }

    /**
     * @param FilterInterface[] ...$filters
     * @return $this
     */
    public function add(FilterInterface ...$filters)
    {
        foreach ($filters as $filter) {
            $this->filters[] = $filter;
        }

        return $this;
    }

    /**
     * @param FilterInterface $filter
     * @return bool
     */
    public function has(FilterInterface $filter)
    {
        return array_search($filter, $this->filters, true) !== false;
    }

    /**
     * @param FilterInterface[] ...$filters
     * @return $this
     */
    public function remove(FilterInterface ...$filters)
    {
        foreach ($filters as $filter) {
            if (($i = array_search($filter, $this->filters, true)) !== false) {
                unset($this->filters[$i]);
            }
        }

        return $this;
    }

    /**
     * @param FilterInterface[] ...$filters
     * @return $this
     */
    public function set(FilterInterface ...$filters)
    {
        $this->filters = $filters;

        return $this;
    }

    /**
     * @return FilterInterface[]
     */
    public function get() : array
    {
        return $this->filters;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1() : AbstractType
    {
        return Asn1::context(self::CHOICE_TAG, Asn1::setOf(
            ...array_map(function ($filter) {
                /** @var FilterInterface $filter */
                return $filter->toAsn1();
            }, $this->filters)
        ));
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
    }
}
