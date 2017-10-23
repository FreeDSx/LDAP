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

/**
 * An interface used for filters that contain other filters.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface FilterContainerInterface
{
    /**
     * @param FilterInterface[] ...$filters
     * @return $this
     */
    public function add(FilterInterface ...$filters);

    /**
     * @param FilterInterface[] ...$filters
     * @return $this
     */
    public function set(FilterInterface ...$filters);

    /**
     * @return FilterInterface[]|FilterContainerInterface[]
     */
    public function get() : array;
}
