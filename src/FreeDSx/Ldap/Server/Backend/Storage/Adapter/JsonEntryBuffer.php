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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use Closure;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use Generator;

/**
 * A transient EntryStorageInterface view over an in-flight JSON data buffer.
 *
 * Created by JsonFileStorage::atomic() for the duration of a single locked
 * read-modify-write cycle. Changes are held in memory and written back when
 * the atomic operation completes.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class JsonEntryBuffer implements EntryStorageInterface
{
    use DefaultHasChildrenTrait;

    /**
     * @var array<string, mixed>
     */
    private array $data;

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

    /**
     * @return Generator<Entry>
     */
    public function list(Dn $baseDn, bool $subtree): Generator
    {
        $normBase = $baseDn->toString();

        foreach ($this->data as $normDn => $entryData) {
            if ($normBase === '' && $subtree) {
                yield ($this->toEntry)($entryData);
            } elseif ($subtree) {
                if ($normDn === $normBase || str_ends_with($normDn, ',' . $normBase)) {
                    yield ($this->toEntry)($entryData);
                }
            } else {
                if ((new Dn($normDn))->isChildOf($baseDn)) {
                    yield ($this->toEntry)($entryData);
                }
            }
        }
    }

    public function store(Entry $entry): void
    {
        $this->data[$entry->getDn()->normalize()->toString()] = ($this->fromEntry)($entry);
    }

    public function remove(Dn $dn): void
    {
        unset($this->data[$dn->toString()]);
    }

    public function atomic(callable $operation): void
    {
        $operation($this);
    }

    /**
     * @return array<string, mixed>
     */
    public function getData(): array
    {
        return $this->data;
    }
}
