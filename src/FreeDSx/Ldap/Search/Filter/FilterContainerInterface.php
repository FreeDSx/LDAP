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

/**
 * An interface used for filters that contain other filters.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface FilterContainerInterface extends FilterInterface
{
    /**
     * Add a filter.
     */
    public function add(FilterInterface ...$filters): self;

    /**
     * Get the filters.
     *
     * @return array<FilterInterface|FilterContainerInterface>
     */
    public function get(): array;

    /**
     * Check if a filter exists.
     */
    public function has(FilterInterface $filter): bool;

    /**
     * Remove a specific filter.
     */
    public function remove(FilterInterface ...$filters): self;

    /**
     * Set the filters.
     */
    public function set(FilterInterface ...$filters): self;
}
