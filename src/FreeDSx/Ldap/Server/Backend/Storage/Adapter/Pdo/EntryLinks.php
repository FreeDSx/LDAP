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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoEntryDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoColumnCastTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PooledStatement;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use Generator;

use function count;
use function is_array;
use function max;
use function min;

/**
 * The values a linked attribute holds, kept as references to entries and resolved to their current DNs.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class EntryLinks
{
    use PdoColumnCastTrait;

    /**
     * Rows read before their links are fetched, so a page costs one statement rather than one per entry.
     */
    private const ENTRIES_PER_FETCH = 100;

    public function __construct(
        private PdoEntryDialectInterface $dialect,
        private PdoStatementPool $statements,
        private LinkedAttributes $declared,
    ) {}

    /**
     * Whether a read pays for links: not when none are declared, nor when the projection names none of them.
     *
     * @param array<string, true>|null $allowed Base names being materialized, or null for all of them.
     */
    public function hydrates(?array $allowed): bool
    {
        if ($this->declared->isEmpty() || $allowed === []) {
            return false;
        }
        if ($allowed === null) {
            return true;
        }

        foreach ($this->declared->names() as $name) {
            if (isset($allowed[$name])) {
                return true;
            }
        }

        return false;
    }

    /**
     * One entry's links, keyed by lowercased attribute name.
     *
     * @return array<string, list<string>>
     */
    public function forEntry(int $entryId): array
    {
        $stmt = $this->statements->execute(
            $this->dialect->queryLinksForEntry(),
            [$entryId],
        );
        $links = [];

        foreach ($this->rowsOf($stmt) as $row) {
            $links[$this->stringColumn($row['attr_name_lower'] ?? null)][] = $this->stringColumn($row['dn'] ?? null);
        }

        return $links;
    }

    /**
     * Pairs each row with its links, reading them a chunk at a time so the caller holds no buffer of its own.
     *
     * @param iterable<int, mixed> $rows Rows as the driver returned them, narrowed here rather than by the caller.
     * @return Generator<int, array{mixed, array<string, list<string>>}>
     */
    public function hydrating(iterable $rows): Generator
    {
        $chunk = [];

        foreach ($rows as $row) {
            $chunk[] = $row;

            if (count($chunk) < self::ENTRIES_PER_FETCH) {
                continue;
            }
            yield from $this->paired($chunk);

            $chunk = [];
        }

        yield from $this->paired($chunk);
    }

    /**
     * @param list<mixed> $chunk
     * @return Generator<int, array{mixed, array<string, list<string>>}>
     */
    private function paired(array $chunk): Generator
    {
        if ($chunk === []) {
            return;
        }
        $links = $this->forRange($chunk);

        foreach ($chunk as $row) {
            yield [
                $row,
                $links[$this->entryIdOf($row)] ?? [],
            ];
        }
    }

    /**
     * A chunk's links in one statement. Ids from a keyset walk are contiguous, so the span is the cheap predicate.
     *
     * @param list<mixed> $chunk
     * @return array<int, array<string, list<string>>>
     */
    private function forRange(array $chunk): array
    {
        $ids = [];

        foreach ($chunk as $row) {
            $id = $this->entryIdOf($row);
            if ($id !== 0) {
                $ids[] = $id;
            }
        }

        if ($ids === []) {
            return [];
        }
        $stmt = $this->statements->execute(
            $this->dialect->queryLinksForRange(),
            [
                min($ids),
                max($ids),
            ],
        );
        $links = [];

        foreach ($this->rowsOf($stmt) as $row) {
            $links[$this->intColumn($row['owner_entry_id'] ?? null)]
                [$this->stringColumn($row['attr_name_lower'] ?? null)][]
                    = $this->stringColumn($row['dn'] ?? null);
        }

        return $links;
    }

    /**
     * The statement's rows, since a pooled statement hands them over one at a time.
     *
     * @return Generator<int, array<array-key, mixed>>
     */
    private function rowsOf(PooledStatement $statement): Generator
    {
        while (($row = $statement->fetch()) !== false) {
            if (is_array($row)) {
                yield $row;
            }
        }
    }

    private function entryIdOf(mixed $row): int
    {
        if (!is_array($row)) {
            return 0;
        }

        return $this->intColumn($row['entry_id'] ?? null);
    }
}
