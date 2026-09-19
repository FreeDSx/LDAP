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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoLinkDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoColumnCastTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PooledStatement;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use Generator;

use function array_map;
use function array_slice;
use function count;
use function is_array;
use function iterator_to_array;
use function max;
use function min;
use function sprintf;

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
        private PdoLinkDialectInterface $dialect,
        private PdoConnection $connection,
        private LinkedAttributes $declared,
    ) {}

    /**
     * Whether a read pays for links: not when none are declared, nor when the projection names none of them.
     */
    public function hydrates(EntryProjection $projection): bool
    {
        $allowed = $projection->allowed();

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
     * One entry's links, keyed by the name each attribute is returned under.
     *
     * @return array<string, list<string>>
     */
    public function forEntry(
        int $entryId,
        EntryProjection $projection,
    ): array {
        return $this->forSpan(
            $entryId,
            $entryId,
            $projection->linkCap,
        )[$entryId] ?? [];
    }

    /**
     * Pairs each row with its links, reading them a chunk at a time so the caller holds no buffer of its own.
     *
     * @param iterable<int, mixed> $rows Rows as the driver returned them, narrowed here rather than by the caller.
     * @return Generator<int, array{mixed, array<string, list<string>>}>
     */
    public function hydrating(
        iterable $rows,
        EntryProjection $projection,
    ): Generator {
        $chunk = [];

        foreach ($rows as $row) {
            $chunk[] = $row;

            if (count($chunk) < self::ENTRIES_PER_FETCH) {
                continue;
            }
            yield from $this->paired(
                $chunk,
                $projection->linkCap,
            );

            $chunk = [];
        }

        yield from $this->paired(
            $chunk,
            $projection->linkCap,
        );
    }

    /**
     * @param list<mixed> $chunk
     * @return Generator<int, array{mixed, array<string, list<string>>}>
     */
    private function paired(
        array $chunk,
        ?int $cap,
    ): Generator {
        if ($chunk === []) {
            return;
        }
        $links = $this->forChunk(
            $chunk,
            $cap,
        );

        foreach ($chunk as $row) {
            yield [
                $row,
                $links[$this->entryIdOf($row)] ?? [],
            ];
        }
    }

    /**
     * Ids from a keyset walk are contiguous, so the chunk's span is the cheap predicate.
     *
     * @param list<mixed> $chunk
     * @return array<int, array<string, list<string>>>
     */
    private function forChunk(
        array $chunk,
        ?int $cap,
    ): array {
        $ids = [];

        foreach ($chunk as $row) {
            $id = $this->entryIdOf($row);
            if ($id !== 0) {
                $ids[] = $id;
            }
        }

        return $ids === []
            ? []
            : $this->forSpan(
                min($ids),
                max($ids),
                $cap,
            );
    }

    /**
     * Reads optimistically: a span holding no more links than the cap cannot hold an attribute over it.
     *
     * @return array<int, array<string, list<string>>>
     */
    private function forSpan(
        int $first,
        int $last,
        ?int $cap,
    ): array {
        if ($cap === null) {
            return $this->grouped(
                $this->rowsOf($this->connection->execute(
                    $this->dialect->queryLinksForRange(),
                    [
                        $first,
                        $last,
                    ],
                )),
                null,
            );
        }
        $rows = iterator_to_array(
            $this->rowsOf($this->connection->execute(
                $this->dialect->queryLinksForRangeUpTo(),
                [
                    $first,
                    $last,
                    $cap + 1,
                ],
            )),
            false,
        );

        return $this->grouped(
            count($rows) > $cap
                ? $this->cappedRows(
                    $first,
                    $last,
                    $cap,
                )
                : $rows,
            $cap,
        );
    }

    /**
     * The span's links with each attribute over the cap read only as far as it, so no read grows with a group's size.
     *
     * @return Generator<int, array<array-key, mixed>>
     */
    private function cappedRows(
        int $first,
        int $last,
        int $cap,
    ): Generator {
        $oversized = iterator_to_array(
            $this->rowsOf($this->connection->execute(
                $this->dialect->queryOversizedLinks(),
                [
                    $first,
                    $last,
                    $cap,
                ],
            )),
            false,
        );

        yield from $this->rowsOf($this->connection->execute(
            $oversized === []
                ? $this->dialect->queryLinksForRange()
                : $this->dialect->queryLinksForRangeExcept(count($oversized)),
            $this->exceptParams(
                $first,
                $last,
                $oversized,
            ),
        ));

        foreach ($oversized as $pair) {
            yield from $this->rowsOf($this->connection->execute(
                $this->dialect->queryLinksForAttribute(),
                [
                    $this->intColumn($pair['owner_entry_id'] ?? null),
                    $this->stringColumn($pair['attr_name_lower'] ?? null),
                    $cap + 1,
                ],
            ));
        }
    }

    /**
     * @param list<array<array-key, mixed>> $oversized
     * @return list<int|string>
     */
    private function exceptParams(
        int $first,
        int $last,
        array $oversized,
    ): array {
        $params = [
            $first,
            $last,
        ];

        foreach ($oversized as $pair) {
            $params[] = $this->intColumn($pair['owner_entry_id'] ?? null);
            $params[] = $this->stringColumn($pair['attr_name_lower'] ?? null);
        }

        return $params;
    }

    /**
     * Keyed by owner, then by the name each attribute is returned under.
     *
     * @param iterable<array<array-key, mixed>> $rows
     * @return array<int, array<string, list<string>>>
     */
    private function grouped(
        iterable $rows,
        ?int $cap,
    ): array {
        $links = [];

        foreach ($rows as $row) {
            $links[$this->intColumn($row['owner_entry_id'] ?? null)]
                [$this->stringColumn($row['attr_name_lower'] ?? null)][]
                    = $this->stringColumn($row['dn'] ?? null);
        }

        return $cap === null
            ? $links
            : array_map(
                fn(array $byName): array => $this->bounded(
                    $byName,
                    $cap,
                ),
                $links,
            );
    }

    /**
     * An attribute over the cap is renamed with the range it holds, so it can never pass for the whole value set.
     *
     * @param array<string, list<string>> $byName
     * @return array<string, list<string>>
     */
    private function bounded(
        array $byName,
        int $cap,
    ): array {
        $bounded = [];

        foreach ($byName as $name => $values) {
            if (count($values) <= $cap) {
                $bounded[$name] = $values;

                continue;
            }
            $bounded[sprintf('%s;range=0-%d', $name, $cap - 1)] = array_slice(
                $values,
                0,
                $cap,
            );
        }

        return $bounded;
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
