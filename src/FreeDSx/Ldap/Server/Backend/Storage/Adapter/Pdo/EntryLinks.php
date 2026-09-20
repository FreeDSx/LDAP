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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoLinkReadDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoColumnCastTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PooledStatement;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\LinkedValueLookupInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use Generator;

use function array_chunk;
use function array_keys;
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
final readonly class EntryLinks implements LinkedValueLookupInterface
{
    use PdoColumnCastTrait;

    /**
     * Rows read before their links are fetched, so a page costs one statement rather than one per entry.
     */
    private const ENTRIES_PER_FETCH = 100;

    public function __construct(
        private PdoLinkReadDialectInterface $dialect,
        private PdoConnection $connection,
        private LinkedAttributes $declared,
    ) {}

    /**
     * Which of the named values the entry links, answered without reading the rest of what it links.
     */
    public function heldLinkValues(
        Dn $owner,
        string $attribute,
        array $values,
    ): array {
        $asked = [];

        foreach ($values as $value) {
            $normalized = Dn::normalizedOrNull($value);

            if ($normalized !== null) {
                $asked[$normalized] = $value;
            }
        }

        if ($asked === []) {
            return [];
        }
        $held = [];

        foreach ($this->heldRows($owner, $attribute, array_keys($asked)) as $row) {
            $normalized = $this->stringColumn($row['lc_dn'] ?? null);

            if (isset($asked[$normalized])) {
                $held[] = $asked[$normalized];
            }
        }

        return $held;
    }

    /**
     * One value the entry links, which is all that answering whether it holds the attribute takes.
     */
    public function anyLinkValue(
        Dn $owner,
        string $attribute,
    ): ?string {
        $row = $this->connection
            ->execute(
                $this->dialect->queryAnyLinkValue(),
                [
                    $owner->normalizedString(),
                    Attribute::normalizeName($attribute),
                ],
            )
            ->fetch();

        return is_array($row)
            ? $this->stringColumn($row['dn'] ?? null)
            : null;
    }

    /**
     * Whether a read pays for links: not when none are declared, nor when the projection names none of them.
     */
    public function hydrates(EntryProjection $projection): bool
    {
        $allowed = $projection->allowed();

        if ($this->declared->isEmpty() || $allowed === [] || $projection->linkCap === 0) {
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
        $links = $this->forSpan(
            $entryId,
            $entryId,
            $projection->linkCap,
        )[$entryId] ?? [];

        return $projection->windows === []
            ? $links
            : $this->sliced($entryId, $projection, $links);
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
                $projection,
            );

            $chunk = [];
        }

        yield from $this->paired(
            $chunk,
            $projection,
        );
    }

    /**
     * The attributes a slice was asked of, read again for the values it names rather than the ones held first.
     *
     * @param array<string, list<string>> $links
     *
     * @return array<string, list<string>>
     */
    private function sliced(
        int $entryId,
        EntryProjection $projection,
        array $links,
    ): array {
        // A slice is bounded even where the read itself is not, so nothing asks for a page and receives everything.
        $cap = $projection->linkCap ?? EntryProjection::DEFAULT_LINK_CAP;

        foreach ($projection->windows as $name => $window) {
            // Whatever the capped read returned for it stands for a different slice than the one asked for.
            $held = $this->rangedNames($links, $name);
            unset($links[$name], $links[$held]);
            $size = $window->size($cap);
            $values = $this->valuesOfSlice(
                $entryId,
                $name,
                $window->first,
                $size,
            );
            $more = count($values) > $size;

            if ($more) {
                $values = array_slice($values, 0, $size);
            }

            if ($values === []) {
                continue;
            }

            $links[$window->nameFor($name, count($values), $more)] = $values;
        }

        return $links;
    }

    /**
     * @param array<string, list<string>> $links
     */
    private function rangedNames(
        array $links,
        string $name,
    ): string {
        foreach (array_keys($links) as $held) {
            if (Attribute::normalizeName($held) === $name) {
                return $held;
            }
        }

        return $name;
    }

    /**
     * One attribute's values from where a slice starts, read one past it to tell whether more are held.
     *
     * @return list<string>
     */
    private function valuesOfSlice(
        int $entryId,
        string $name,
        int $first,
        int $size,
    ): array {
        $values = [];
        $rows = $this->rowsOf($this->connection->execute(
            $this->dialect->queryLinksForAttributeFrom(),
            [
                $entryId,
                $name,
                // One past the slice, which is what tells the naming whether more are held behind it.
                $size + 1,
                $first,
            ],
        ));

        foreach ($rows as $row) {
            $values[] = $this->stringColumn($row['dn'] ?? null);
        }

        return $values;
    }

    /**
     * @param list<mixed> $chunk
     * @return Generator<int, array{mixed, array<string, list<string>>}>
     */
    private function paired(
        array $chunk,
        EntryProjection $projection,
    ): Generator {
        if ($chunk === []) {
            return;
        }
        $links = $this->forChunk(
            $chunk,
            $projection->linkCap,
        );

        foreach ($chunk as $row) {
            $entryId = $this->entryIdOf($row);
            $held = $links[$entryId] ?? [];

            yield [
                $row,
                // An entry linking nothing at all has no slice to take, which is most of what a subtree walks.
                $projection->windows === [] || $held === []
                    ? $held
                    : $this->sliced($entryId, $projection, $held),
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
     * @param list<string> $normalized
     *
     * @return Generator<int, array<array-key, mixed>>
     */
    private function heldRows(
        Dn $owner,
        string $attribute,
        array $normalized,
    ): Generator {
        foreach (array_chunk($normalized, self::ENTRIES_PER_FETCH) as $chunk) {
            $params = [
                $owner->normalizedString(),
                Attribute::normalizeName($attribute),
                ...$chunk,
            ];

            yield from $this->rowsOf($this->connection->execute(
                $this->dialect->queryHeldLinkValues(count($chunk)),
                $params,
            ));
        }
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
