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

use FreeDSx\Ldap\Exception\InvalidArgumentException;

/**
 * Represents a collection of entry objects.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Entries implements \Countable, \IteratorAggregate
{
    /**
     * @var Entry[]
     */
    protected $entries = [];

    /**
     * @param Entry ...$entries
     */
    public function __construct(Entry ...$entries)
    {
        $this->entries = $entries;
    }

    /**
     * @param Entry ...$entries
     * @return $this
     */
    public function add(Entry ...$entries)
    {
        $this->entries = \array_merge($this->entries, $entries);

        return $this;
    }

    /**
     * @param Entry ...$entries
     * @return $this
     */
    public function remove(Entry ...$entries)
    {
        foreach ($entries as $entry) {
            if (($index = \array_search($entry, $this->entries, true)) !== false) {
                unset($this->entries[$index]);
            }
        }

        return $this;
    }

    /**
     * Check whether or not an entry (either an Entry object or string DN) exists within the entries.
     *
     * @param Entry|Dn|string $entry
     * @return bool
     */
    public function has($entry): bool
    {
        if ($entry instanceof Entry) {
            return (\array_search($entry, $this->entries, true) !== false);
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
     *
     * @param string $dn
     * @return Entry|null
     */
    public function get(string $dn): ?Entry
    {
        foreach ($this->entries as $entry) {
            if ($entry->getDn()->toString() === $dn) {
                return $entry;
            }
        }

        return null;
    }

    /**
     * Get the first entry object, if one exists.
     *
     * @return Entry|null
     */
    public function first(): ?Entry
    {
        $entry = \reset($this->entries);

        return $entry === false ? null : $entry;
    }

    /**
     * Get the last entry object, if one exists.
     *
     * @return Entry|null
     */
    public function last(): ?Entry
    {
        $entry = \end($this->entries);
        \reset($this->entries);

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
     * @return \ArrayIterator
     */
    public function getIterator()
    {
        return new \ArrayIterator($this->entries);
    }

    /**
     * @return int
     */
    public function count()
    {
        return \count($this->entries);
    }
}
