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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\LinkKeys;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoColumnCastTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PooledStatement;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDirection;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\Backlinks;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use Generator;

use function array_map;
use function array_slice;
use function count;
use function is_array;
use function iterator_to_array;
use function sprintf;

/**
 * Reads one direction of the link table for the entries a set of keys covers.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LinkReader
{
    use PdoColumnCastTrait;

    private string $span;

    private string $spanUpTo;

    private string $spanOversized;

    private string $attribute;

    private string $attributeFrom;

    private Backlinks $backlinks;

    /**
     * @var array<string, list<string>> The names each stored attribute's values are returned under.
     */
    private array $returnedAs;

    public function __construct(
        private PdoLinkReadDialectInterface&PdoBacklinkReadDialectInterface $dialect,
        private PdoConnection $connection,
        private LinkDirection $direction,
        LinkedAttributes $linked,
    ) {
        // Resolved here rather than in a method of its own because PhpStan doesn't support that :/
        $backward = $direction === LinkDirection::Backward;
        $this->backlinks = $linked->backlinks();
        $this->returnedAs = self::returnedAs(
            $direction,
            $linked,
        );

        $this->attribute = $backward
            ? $dialect->queryBacklinksForAttribute()
            : $dialect->queryLinksForAttribute();
        $this->attributeFrom = $backward
            ? $dialect->queryBacklinksForAttributeFrom()
            : $dialect->queryLinksForAttributeFrom();

        // Single entries and walks in key order read by a span, whose statements do not vary with the ids.
        $span = LinkKeys::span(
            0,
            0,
        );
        $idle = $this->isIdle();
        $this->span = $idle
            ? ''
            : $this->built($span);
        $this->spanUpTo = $idle
            ? ''
            : $this->builtUpTo($span);
        $this->spanOversized = $idle
            ? ''
            : $this->builtOversized($span);
    }

    /**
     * Whether the direction has anything to read.
     */
    public function isIdle(): bool
    {
        return $this->direction === LinkDirection::Backward
            && $this->backlinks->isEmpty();
    }

    /**
     * Reads optimistically: entries holding no more links between them than the cap cannot hold an attribute over it.
     *
     * @return array<int, array<string, list<string>>>
     */
    public function forKeys(
        LinkKeys $keys,
        ?int $cap,
    ): array {
        if ($this->isIdle()) {
            return [];
        }

        if ($cap === null) {
            return $this->grouped(
                $this->rowsOf($this->connection->execute(
                    $this->query($keys),
                    $keys->params(),
                )),
                null,
            );
        }
        $rows = iterator_to_array(
            $this->rowsOf($this->connection->execute(
                $this->queryUpTo($keys),
                [
                    ...$keys->params(),
                    $cap + 1,
                ],
            )),
            false,
        );

        return $this->grouped(
            count($rows) > $cap
                ? $this->cappedRows(
                    $keys,
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

    private function query(LinkKeys $keys): string
    {
        return $keys->isSpan()
            ? $this->span
            : $this->built($keys);
    }

    private function queryUpTo(LinkKeys $keys): string
    {
        return $keys->isSpan()
            ? $this->spanUpTo
            : $this->builtUpTo($keys);
    }

    private function queryOversized(LinkKeys $keys): string
    {
        return $keys->isSpan()
            ? $this->spanOversized
            : $this->builtOversized($keys);
    }

    private function built(LinkKeys $keys): string
    {
        return match ($this->direction) {
            LinkDirection::Forward => $this->dialect->queryLinksFor($keys),
            LinkDirection::Backward => $this->dialect->queryBacklinksFor(
                $this->backlinks->linkedNames(),
                $keys,
            ),
        };
    }

    private function builtUpTo(LinkKeys $keys): string
    {
        return match ($this->direction) {
            LinkDirection::Forward => $this->dialect->queryLinksForUpTo($keys),
            LinkDirection::Backward => $this->dialect->queryBacklinksForUpTo(
                $this->backlinks->linkedNames(),
                $keys,
            ),
        };
    }

    private function builtOversized(LinkKeys $keys): string
    {
        return match ($this->direction) {
            LinkDirection::Forward => $this->dialect->queryOversizedLinks($keys),
            LinkDirection::Backward => $this->dialect->queryOversizedBacklinks(
                $this->backlinks->linkedNames(),
                $keys,
            ),
        };
    }

    /**
     * Varies with how many pairs are excluded.
     */
    private function queryExcept(
        LinkKeys $keys,
        int $count,
    ): string {
        return match ($this->direction) {
            LinkDirection::Forward => $this->dialect->queryLinksForExcept(
                $keys,
                $count,
            ),
            LinkDirection::Backward => $this->dialect->queryBacklinksForExcept(
                $this->backlinks->linkedNames(),
                $keys,
                $count,
            ),
        };
    }

    /**
     * The covered entries' links with each attribute over the cap read only as far as it.
     *
     * @return Generator<int, array<array-key, mixed>>
     */
    private function cappedRows(
        LinkKeys $keys,
        int $cap,
    ): Generator {
        $oversized = iterator_to_array(
            $this->rowsOf($this->connection->execute(
                $this->queryOversized($keys),
                [
                    ...$keys->params(),
                    $cap,
                ],
            )),
            false,
        );

        yield from $this->rowsOf($this->connection->execute(
            $oversized === []
                ? $this->query($keys)
                : $this->queryExcept(
                    $keys,
                    count($oversized),
                ),
            $this->exceptParams(
                $keys,
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
        LinkKeys $keys,
        array $oversized,
    ): array {
        $params = $keys->params();

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

            foreach ($this->returnedAs[$stored] ?? [$stored] as $name) {
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
     * @return array<string, list<string>>
     */
    private static function returnedAs(
        LinkDirection $direction,
        LinkedAttributes $linked,
    ): array {
        $returnedAs = [];
        $backlinks = $linked->backlinks();

        if ($direction === LinkDirection::Backward) {
            foreach ($backlinks->linkedNames() as $stored) {
                $returnedAs[$stored] = $backlinks->reversing($stored);
            }

            return $returnedAs;
        }

        foreach ($linked->names() as $stored) {
            $returnedAs[$stored] = [$linked->primaryName($stored)];
        }

        return $returnedAs;
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
