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
     */
    private array $changes;

    public function __construct(Change ...$changes)
    {
        $this->changes = $changes;
    }

    /**
     * Add a change to the list.
     */
    public function add(Change ...$changes): self
    {
        foreach ($changes as $change) {
            $this->changes[] = $change;
        }

        return $this;
    }

    /**
     * Check if the change is in the change list.
     */
    public function has(Change $change): bool
    {
        return in_array(
            $change,
            $this->changes,
            true
        );
    }

    /**
     * Remove a change from the list.
     */
    public function remove(Change ...$changes): self
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
     */
    public function reset(): self
    {
        $this->changes = [];

        return $this;
    }

    /**
     * Set the change list to just these changes.
     */
    public function set(Change ...$changes): self
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
     * @return  Traversable<int, Change>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->changes);
    }
}
