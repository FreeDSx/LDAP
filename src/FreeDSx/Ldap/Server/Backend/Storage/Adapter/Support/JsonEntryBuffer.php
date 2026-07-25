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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support;

use Closure;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeAppenderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use Generator;

/**
 * Transient EntryStorageInterface view used by JsonFileStorage::atomic() for one locked read-modify-write cycle.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class JsonEntryBuffer implements EntryStorageInterface, ChangeAppenderInterface
{
    use DefaultHasChildrenTrait;

    /**
     * @var array<string, mixed>
     */
    private array $data;

    /**
     * @var list<PendingChange>
     */
    private array $pending = [];

    /**
     * @param array<string, mixed> $data
     * @param Closure(mixed): Entry $toEntry
     * @param Closure(Entry): array<string, mixed> $fromEntry
     */
    public function __construct(
        array $data,
        private readonly Closure $toEntry,
        private readonly Closure $fromEntry,
    ) {
        $this->data = $data;
    }

    public function find(Dn $dn): ?Entry
    {
        $key = $dn->toString();
        if (!isset($this->data[$key])) {
            return null;
        }

        return ($this->toEntry)($this->data[$key]);
    }

    public function exists(Dn $dn): bool
    {
        return isset($this->data[$dn->toString()]);
    }

    public function list(StorageListOptions $options): EntryStream
    {
        return new EntryStream($this->generateEntries($options));
    }

    public function store(
        Entry $entry,
        bool $rebuildIndexes = false,
    ): void {
        $this->data[$entry->getDn()->normalize()->toString()] = ($this->fromEntry)($entry);
    }

    public function remove(Dn $dn): void
    {
        unset($this->data[$dn->toString()]);
    }

    public function removeAll(array $dns): void
    {
        foreach ($dns as $dn) {
            $this->remove($dn);
        }
    }

    public function atomic(callable $operation): void
    {
        $operation($this);
    }

    public function appendChange(PendingChange $change): void
    {
        $this->pending[] = $change;
    }

    /**
     * Changes collected during this write cycle, for the storage to flush to the journal after it commits.
     *
     * @return list<PendingChange>
     */
    public function getPendingChanges(): array
    {
        return $this->pending;
    }

    public function namingContexts(): array
    {
        $roots = [];

        foreach (array_keys($this->data) as $normDn) {
            $parent = (new Dn($normDn))->getParent()?->normalize()->toString() ?? '';
            if ($parent === '' || !isset($this->data[$parent])) {
                $roots[] = new Dn($normDn);
            }
        }

        return $roots;
    }

    /**
     * @return array<string, mixed>
     */
    public function getData(): array
    {
        return $this->data;
    }

    /**
     * @return Generator<Entry>
     */
    private function generateEntries(StorageListOptions $options): Generator
    {
        $deadline = $options->timeLimit > 0
            ? microtime(true) + $options->timeLimit
            : null;

        foreach ($this->data as $normDn => $entryData) {
            if ($deadline !== null && microtime(true) >= $deadline) {
                throw new TimeLimitExceededException();
            }

            $entryDn = new Dn($normDn);

            if ($options->subtree && $entryDn->isDescendantOf($options->baseDn)) {
                yield ($this->toEntry)($entryData);
            } elseif (!$options->subtree && $entryDn->isChildOf($options->baseDn)) {
                yield ($this->toEntry)($entryData);
            }
        }
    }
}
