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

namespace Tests\Support\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;

use function array_map;
use function array_unique;
use function array_values;
use function implode;
use function strtolower;

/**
 * Records the deletions a persist phase delivers, by name, and whether a marker entry written after them arrived.
 */
final class PersistDeletionLog
{
    /**
     * @var array<string, string> each entry's name, by its lowercased entryUUID
     */
    private array $names = [];

    /**
     * @var list<string>
     */
    private array $deliveries = [];

    /**
     * @var list<string>
     */
    private array $deleted = [];

    private ?SyncIdSetResult $firstSet = null;

    private bool $isMarked = false;

    public function __construct(private readonly string $markerDn) {}

    /**
     * @param array<string, string> $names each entry's name, by its entryUUID
     */
    public function useNames(array $names): void
    {
        foreach ($names as $uuid => $name) {
            $this->names[strtolower($uuid)] = $name;
        }
    }

    public function recordSet(SyncIdSetResult $result): void
    {
        $this->firstSet ??= $result;
        $names = $this->namesOf($result->getDecodedEntryUuids());
        $this->deliveries[] = 'set[' . implode(
            ', ',
            $names,
        ) . ']';
        $this->deleted = [...$this->deleted, ...$names];
    }

    public function recordEntry(SyncEntryResult $result): void
    {
        if (strtolower($result->getEntry()->getDn()->toString()) === strtolower($this->markerDn)) {
            $this->isMarked = true;
        }
        if (!$result->isDelete()) {
            return;
        }

        $name = $this->namesOf([$result->getDecodedEntryUuid()])[0];
        $this->deliveries[] = 'delete[' . $name . ']';
        $this->deleted[] = $name;
    }

    /**
     * Whether the marker's add has arrived; a poll sends it before the deletions it holds.
     */
    public function isMarked(): bool
    {
        return $this->isMarked;
    }

    public function firstSet(): ?SyncIdSetResult
    {
        return $this->firstSet;
    }

    /**
     * @return list<string>
     */
    public function expectedNames(): array
    {
        return array_values($this->names);
    }

    /**
     * Each name reported deleted, once however often a provider sent its deletion.
     *
     * @return list<string>
     */
    public function deletedNames(): array
    {
        return array_values(array_unique($this->deleted));
    }

    public function summary(): string
    {
        return 'Received: ' . implode(
            ', ',
            $this->deliveries,
        );
    }

    /**
     * @param array<string> $uuids
     * @return list<string>
     */
    private function namesOf(array $uuids): array
    {
        return array_values(array_map(
            fn(string $uuid): string => $this->names[strtolower($uuid)] ?? 'unknown:' . $uuid,
            $uuids,
        ));
    }
}
