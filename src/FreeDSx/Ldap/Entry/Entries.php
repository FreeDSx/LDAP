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
use Stringable;
use Traversable;
use function array_merge;
use function array_search;
use function count;
use function end;
use function in_array;
use function reset;

/**
 * Represents a collection of entry objects.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * @template T of Entry
 */
class Entries implements Countable, IteratorAggregate
{
    /**
     * @var array<T>
     */
    private array $entries;

    /**
     * @param T ...$entries
     */
    public function __construct(Entry ...$entries)
    {
        $this->entries = $entries;
    }

    /**
     * @param T ...$entries
     * @return $this
     */
    public function add(Entry ...$entries): self
    {
        $this->entries = array_merge($this->entries, $entries);

        return $this;
    }

    /**
     * @param T ...$entries
     * @return $this
     */
    public function remove(Entry ...$entries): self
    {
        foreach ($entries as $entry) {
            if (($index = array_search($entry, $this->entries, true)) !== false) {
                unset($this->entries[$index]);
            }
        }

        return $this;
    }

    /**
     * Check whether an entry (either an Entry object or string DN) exists within the entries.
     */
    public function has(Entry|Dn|string $entry): bool
    {
        if ($entry instanceof Entry) {
            return in_array(
                $entry,
                $this->entries,
                true
            );
        }

        foreach ($this->entries as $entryObj) {
            if ((string) $entry === $entryObj->getDn()->toString()) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get an entry from the collection by its DN.
     */
    public function get(Stringable|string $dn): ?Entry
    {
        foreach ($this->entries as $entry) {
            if ($entry->getDn()->toString() === (string) $dn) {
                return $entry;
            }
        }

        return null;
    }

    /**
     * Get the first entry object, if one exists.
     */
    public function first(): ?Entry
    {
        $entry = reset($this->entries);

        return $entry === false ? null : $entry;
    }

    /**
     * Get the last entry object, if one exists.
     */
    public function last(): ?Entry
    {
        $entry = end($this->entries);
        reset($this->entries);

        return $entry === false ? null : $entry;
    }

    /**
     * @return Entry[]
     */
    public function toArray(): array
    {
        return $this->entries;
    }

    /**
     * @inheritDoc
     *
     * @return Traversable<Entry>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->entries);
    }

    /**
     * @inheritDoc
     */
    public function count(): int
    {
        return count($this->entries);
    }
}
