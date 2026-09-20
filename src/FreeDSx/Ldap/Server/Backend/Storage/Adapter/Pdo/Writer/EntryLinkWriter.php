<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra @gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoLinkWriteDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoLinkReadDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoColumnCastTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\LinkedValueLookupInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use Generator;

use function array_chunk;
use function count;
use function is_array;
use function ksort;

/**
 * Keeps an entry's linked values in the table they are stored in, and answers what it links there.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class EntryLinkWriter implements LinkedValueLookupInterface
{
    use PdoColumnCastTrait;

    /**
     * Links per statement. Four placeholders each, inside the 999 bound SQLite builds before 3.32 compile in.
     */
    private const LINKS_PER_STATEMENT = 200;

    /**
     * DNs per resolving statement, one placeholder each.
     */
    private const DNS_PER_STATEMENT = 500;

    public function __construct(
        private PdoLinkWriteDialectInterface&PdoLinkReadDialectInterface $dialect,
        private PdoConnection $connection,
        private LinkedAttributes $linked,
        private PendingLinkWriter $pending,
    ) {}

    /**
     * Brings the entry's links to what it now holds, touching only the rows that differ.
     */
    public function write(
        int $ownerId,
        Entry $entry,
    ): void {
        if ($this->linked->isEmpty()) {
            return;
        }
        $values = $this->linked->valuesOf($entry);
        $resolved = $this->resolve($values);
        $wanted = $this->wantedLinks($values, $resolved);
        $held = $this->heldLinks($ownerId);

        $this->deleteLinks(
            $ownerId,
            array_diff_key($held, $wanted),
        );
        $this->insertLinks(
            $ownerId,
            array_diff_key($wanted, $held),
        );
        $this->pending->clearFor($ownerId);
        $this->pending->park(
            $ownerId,
            $values,
            $resolved,
        );
    }

    /**
     * The links of an entry that was just created, which holds nothing yet to diff against or clear.
     */
    public function writeNew(
        int $ownerId,
        Entry $entry,
    ): void {
        if ($this->linked->isEmpty()) {
            return;
        }
        $values = $this->linked->valuesOf($entry);

        if ($values === []) {
            return;
        }
        $resolved = $this->resolve($values);

        $this->insertLinks(
            $ownerId,
            $this->wantedLinks($values, $resolved),
        );
        $this->pending->park(
            $ownerId,
            $values,
            $resolved,
        );
    }

    /**
     * Applies only the values the delta names, leaving whatever else the attribute links untouched.
     */
    public function apply(
        int $ownerId,
        LinkDelta $delta,
    ): void {
        $values = [];

        foreach ($delta->names() as $name) {
            $values[$name] = [
                ...$delta->added($name),
                ...$delta->removed($name),
            ];
        }
        $resolved = $this->resolve($values);
        $remove = [];
        $add = [];

        // Gathered across every attribute first, since a statement per attribute takes index locks in an order that
        // differs between writers, which concurrent writers deadlock on.
        foreach ($delta->names() as $name) {
            $remove += $this->linksFor($name, $delta->removed($name), $resolved);
            $add += $this->linksFor($name, $delta->added($name), $resolved);
        }

        $this->deleteLinks($ownerId, $remove);
        $this->insertLinks($ownerId, $add);
        $this->pending->park(
            $ownerId,
            $this->unresolvedOf($delta, $resolved),
            $resolved,
        );
    }

    /**
     * Which of the named values the owner links, answered on the connection its own write runs on.
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
        $params = [
            $owner->normalizedString(),
            Attribute::normalizeName($attribute),
            ...array_keys($asked),
        ];

        foreach ($this->rowsOf($this->dialect->queryHeldLinkValues(count($asked)), $params) as $row) {
            $held[] = $asked[$this->stringColumn($row['lc_dn'] ?? null)] ?? null;
        }

        return array_values(array_filter($held));
    }

    /**
     * One value the owner links, which is all that answering whether it holds the attribute takes.
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
     * The links the named values stand for, skipping any naming an entry that is not stored.
     *
     * @param list<string> $values
     * @param array<string, int> $resolved
     *
     * @return array<string, array{string, int, string}>
     */
    private function linksFor(
        string $name,
        array $values,
        array $resolved,
    ): array {
        return $this->wantedLinks(
            [$name => $values],
            $resolved,
        );
    }

    /**
     * The added values naming an entry that is not stored, which are parked rather than refused.
     *
     * @param array<string, int> $resolved
     *
     * @return array<string, list<string>>
     */
    private function unresolvedOf(
        LinkDelta $delta,
        array $resolved,
    ): array {
        $pending = [];

        foreach ($delta->names() as $name) {
            $unresolved = [];

            foreach ($delta->added($name) as $value) {
                $normalized = Dn::normalizedOrNull($value);

                if ($normalized === null || !isset($resolved[$normalized])) {
                    $unresolved[] = $value;
                }
            }

            if ($unresolved !== []) {
                $pending[$name] = $unresolved;
            }
        }

        return $pending;
    }

    /**
     * The ids of the DNs the entry names, keyed by their normalised form.
     *
     * @param array<string, list<string>> $values
     *
     * @return array<string, int>
     */
    private function resolve(array $values): array
    {
        $wanted = [];

        foreach ($values as $attributeValues) {
            foreach ($attributeValues as $value) {
                $normalized = Dn::normalizedOrNull($value);

                if ($normalized !== null) {
                    $wanted[$normalized] = true;
                }
            }
        }

        if ($wanted === []) {
            return [];
        }
        $ids = [];

        foreach (array_chunk(array_keys($wanted), self::DNS_PER_STATEMENT) as $chunk) {
            foreach ($this->rowsOf($this->dialect->queryResolveDns(count($chunk)), $chunk) as $row) {
                $ids[$this->stringColumn($row['lc_dn'] ?? null)] = $this->intColumn($row['entry_id'] ?? null);
            }
        }

        return $ids;
    }

    /**
     * The links the entry now stands for, keyed so that two spellings of one target collapse to one row.
     *
     * @param array<string, list<string>> $values
     * @param array<string, int> $resolved
     *
     * @return array<string, array{string, int, string}>
     */
    private function wantedLinks(
        array $values,
        array $resolved,
    ): array {
        $links = [];

        foreach ($values as $name => $attributeValues) {
            foreach ($attributeValues as $value) {
                $normalized = Dn::normalizedOrNull($value);
                $targetId = $normalized === null
                    ? null
                    : $resolved[$normalized] ?? null;

                if ($targetId === null) {
                    continue;
                }

                $links[$this->keyOf($name, $targetId, '')] = [$name, $targetId, ''];
            }
        }

        return $links;
    }

    /**
     * The links already stored for the owner, keyed the same way as the wanted ones.
     *
     * @return array<string, array{string, int, string}>
     */
    private function heldLinks(int $ownerId): array
    {
        $links = [];

        foreach ($this->rowsOf($this->dialect->queryLinkIdsForOwner(), [$ownerId]) as $row) {
            $name = $this->stringColumn($row['attr_name_lower'] ?? null);
            $targetId = $this->intColumn($row['target_entry_id'] ?? null);
            $uid = $this->stringColumn($row['target_uid'] ?? null);

            $links[$this->keyOf($name, $targetId, $uid)] = [$name, $targetId, $uid];
        }

        return $links;
    }

    /**
     * @param array<string, array{string, int, string}> $links
     */
    private function deleteLinks(
        int $ownerId,
        array $links,
    ): void {
        if ($links === []) {
            return;
        }

        // Ordered the same way by every writer, since a statement per attribute takes index locks in an order that
        // differs between them, which concurrent writers deadlock on.
        ksort($links);

        foreach (array_chunk($links, self::LINKS_PER_STATEMENT) as $chunk) {
            $params = [$ownerId];

            foreach ($chunk as [$name, $targetId, $uid]) {
                $params[] = $name;
                $params[] = $targetId;
                $params[] = $uid;
            }

            $this->connection->execute(
                $this->dialect->queryDeleteLinks(count($chunk)),
                $params,
            );
        }
    }

    /**
     * @param array<string, array{string, int, string}> $links
     */
    private function insertLinks(
        int $ownerId,
        array $links,
    ): void {
        if ($links === []) {
            return;
        }
        ksort($links);

        foreach (array_chunk($links, self::LINKS_PER_STATEMENT) as $chunk) {
            $params = [];

            foreach ($chunk as [$name, $targetId, $uid]) {
                $params[] = $ownerId;
                $params[] = $name;
                $params[] = $targetId;
                $params[] = $uid;
            }

            $this->connection->execute(
                $this->dialect->queryInsertLinks(count($chunk)),
                $params,
            );
        }
    }

    private function keyOf(
        string $name,
        int $targetId,
        string $uid,
    ): string {
        return $name . "\0" . $targetId . "\0" . $uid;
    }

    /**
     * @param list<string|int> $params
     *
     * @return Generator<int, array<array-key, mixed>>
     */
    private function rowsOf(
        string $sql,
        array $params,
    ): Generator {
        $statement = $this->connection->execute($sql, $params);

        while (($row = $statement->fetch()) !== false) {
            if (is_array($row)) {
                yield $row;
            }
        }
    }
}
