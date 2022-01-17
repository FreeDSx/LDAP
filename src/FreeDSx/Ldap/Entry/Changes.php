<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Entry;

use ArrayIterator;
use Countable;
use IteratorAggregate;
use Traversable;
use function array_search;
use function count;

/**
 * Represents a set of change objects.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Changes implements Countable, IteratorAggregate
{
    /**
     * @var Change[]
     * @psalm-var list<Change>
     */
    protected $changes = [];

    /**
     * @param Change ...$changes
     */
    public function __construct(Change ...$changes)
    {
        $this->changes = $changes;
    }

    /**
     * Add a change to the list.
     *
     * @param Change ...$changes
     * @return $this
     */
    public function add(Change ...$changes)
    {
        foreach ($changes as $change) {
            $this->changes[] = $change;
        }

        return $this;
    }

    /**
     * Check if the change is in the change list.
     *
     * @param Change $change
     * @return bool
     */
    public function has(Change $change)
    {
        return array_search($change, $this->changes, true) !== false;
    }

    /**
     * Remove a change from the list.
     *
     * @param Change ...$changes
     * @return $this
     */
    public function remove(Change ...$changes)
    {
        foreach ($changes as $change) {
            if (($index = array_search($change, $this->changes, true)) !== false) {
                unset($this->changes[$index]);
            }
        }

        return $this;
    }

    /**
     * Removes all changes from the list.
     *
     * @return $this
     */
    public function reset()
    {
        $this->changes = [];

        return $this;
    }

    /**
     * Set the change list to just these changes.
     *
     * @param Change ...$changes
     * @return $this
     */
    public function set(Change ...$changes)
    {
        $this->changes = $changes;

        return $this;
    }

    /**
     * @return Change[]
     */
    public function toArray(): array
    {
        return $this->changes;
    }

    /**
     * @inheritDoc
     * @psalm-return 0|positive-int
     */
    public function count(): int
    {
        return count($this->changes);
    }

    /**
     * @inheritDoc
     * @psalm-return \ArrayIterator<int, Change>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->changes);
    }
}
