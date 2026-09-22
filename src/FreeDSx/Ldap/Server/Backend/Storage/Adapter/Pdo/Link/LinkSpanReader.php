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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Link;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoBacklinkReadDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoLinkReadDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoColumnCastTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PooledStatement;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDirection;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\Backlinks;
use Generator;

use function array_map;
use function array_slice;
use function count;
use function is_array;
use function iterator_to_array;
use function sprintf;

/**
 * Reads one direction of the link table for a contiguous span of entries.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LinkSpanReader
{
    use PdoColumnCastTrait;

    private string $span;

    private string $spanUpTo;

    private string $oversized;

    private string $attribute;

    private string $attributeFrom;

    /**
     * @param Backlinks $namedAs What each stored attribute is read back under, which reading forwards is nothing.
     */
    public function __construct(
        private PdoLinkReadDialectInterface&PdoBacklinkReadDialectInterface $dialect,
        private PdoConnection $connection,
        private LinkDirection $direction,
        private Backlinks $namedAs = new Backlinks(),
    ) {
        // Resolved here rather than in a method of its own because PhpStan doesn't support that :/
        $backward = $direction === LinkDirection::Backward;
        $names = $namedAs->linkedNames();

        $this->attribute = $backward
            ? $dialect->queryBacklinksForAttribute()
            : $dialect->queryLinksForAttribute();
        $this->attributeFrom = $backward
            ? $dialect->queryBacklinksForAttributeFrom()
            : $dialect->queryLinksForAttributeFrom();

        $idle = $backward && $names === [];
        $this->span = $idle
            ? ''
            : ($backward ? $dialect->queryBacklinksForRange($names) : $dialect->queryLinksForRange());
        $this->spanUpTo = $idle
            ? ''
            : ($backward ? $dialect->queryBacklinksForRangeUpTo($names) : $dialect->queryLinksForRangeUpTo());
        $this->oversized = $idle
            ? ''
            : ($backward ? $dialect->queryOversizedBacklinks($names) : $dialect->queryOversizedLinks());
    }

    /**
     * Whether the direction has anything to read.
     */
    public function isIdle(): bool
    {
        return $this->direction === LinkDirection::Backward
            && $this->namedAs->isEmpty();
    }

    /**
     * Reads optimistically: a span holding no more links than the cap cannot hold an attribute over it.
     *
     * @return array<int, array<string, list<string>>>
     */
    public function forSpan(
        int $first,
        int $last,
        ?int $cap,
    ): array {
        if ($this->isIdle()) {
            return [];
        }

        if ($cap === null) {
            return $this->grouped(
                $this->rowsOf($this->connection->execute(
                    $this->span,
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
                $this->spanUpTo,
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
     * One attribute's values from where a slice starts, read one past it to tell whether more are held.
     *
     * @param string $stored The attribute as the table keys it.
     *
     * @return list<string>
     */
    public function valuesOfSlice(
        int $entryId,
        string $stored,
        int $first,
        int $size,
    ): array {
        $values = [];
        $rows = $this->rowsOf($this->connection->execute(
            $this->attributeFrom,
            [
                $entryId,
                $stored,
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
     * Varies with how many pairs are excluded.
     */
    private function spanExcept(int $count): string
    {
        return match ($this->direction) {
            LinkDirection::Forward => $this->dialect->queryLinksForRangeExcept($count),
            LinkDirection::Backward => $this->dialect->queryBacklinksForRangeExcept(
                $this->namedAs->linkedNames(),
                $count,
            ),
        };
    }

    /**
     * The span's links with each attribute over the cap read only as far as it.
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
                $this->oversized,
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
                ? $this->span
                : $this->spanExcept(count($oversized)),
            $this->exceptParams(
                $first,
                $last,
                $oversized,
            ),
        ));

        foreach ($oversized as $pair) {
            yield from $this->rowsOf($this->connection->execute(
                $this->attribute,
                [
                    $this->intColumn($pair['key_entry_id'] ?? null),
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
            $params[] = $this->intColumn($pair['key_entry_id'] ?? null);
            $params[] = $this->stringColumn($pair['attr_name_lower'] ?? null);
        }

        return $params;
    }

    /**
     * Keyed by entry, then by the name each attribute is returned under.
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
            $stored = $this->stringColumn($row['attr_name_lower'] ?? null);
            $entryId = $this->intColumn($row['key_entry_id'] ?? null);
            $dn = $this->stringColumn($row['dn'] ?? null);

            // Reading forwards the stored name is the one it is read under; reading backwards, every back-link's.
            foreach ($this->namedAs->reversing($stored) ?: [$stored] as $name) {
                $links[$entryId][$name][] = $dn;
            }
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
     * An attribute over the cap is renamed with the range it holds.
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
}
