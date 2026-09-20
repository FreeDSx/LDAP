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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoLinkWriteDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoPendingLinkDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoColumnCastTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\ReferenceIntegrityInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use Generator;

use function array_chunk;
use function count;
use function is_array;
use function ksort;
use function strtolower;

/**
 * Keeps an entry's linked values in the table they are stored in, and parks the ones naming an entry that is not there.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class EntryLinkWriter implements ReferenceIntegrityInterface
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
        private PdoLinkWriteDialectInterface&PdoPendingLinkDialectInterface $dialect,
        private PdoConnection $connection,
        private LinkedAttributes $linked,
    ) {}

    /**
     * Brings the entry's links to what it now holds, touching only the rows that differ.
     */
    public function write(
        int $ownerId,
        Entry $entry,
    ): void {
        $values = $this->linked->valuesOf($entry);

        if ($values === [] && $this->linked->isEmpty()) {
            return;
        }
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
        $this->parkUnresolved(
            $ownerId,
            $values,
            $resolved,
        );
    }

    /**
     * Links whatever was parked for a DN that now exists, or for every DN when none is named.
     */
    public function promote(?Dn $landed = null): void
    {
        $byDn = $landed !== null;
        $params = $byDn
            ? [$landed->normalizedString()]
            : [];

        $this->connection->execute(
            $this->dialect->queryPromotePending($byDn),
            $params,
        );
        $this->connection->execute(
            $this->dialect->queryDeletePromotedPending($byDn),
            $params,
        );
    }

    /**
     * The attribute names holding a value that named an entry which is not stored.
     *
     * @return list<string>
     */
    public function unresolvedReferences(Dn $owner): array
    {
        $ownerId = $this->idOf($owner);

        if ($ownerId === null) {
            return [];
        }
        $names = [];

        foreach ($this->rowsOf($this->dialect->queryPendingNamesForOwner(), [$ownerId]) as $row) {
            $names[] = $this->stringColumn($row['attr_name_lower'] ?? null);
        }

        return $names;
    }

    /**
     * Whether anything at all was parked, which is what a batch asks once rather than per entry.
     */
    public function hasUnresolvedReferences(): bool
    {
        return $this->connection
            ->execute($this->dialect->queryAnyPending())
            ->fetch() !== false;
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

    /**
     * Parks the values naming an entry that is not stored, replacing whatever the owner had parked before.
     *
     * @param array<string, list<string>> $values
     * @param array<string, int> $resolved
     */
    private function parkUnresolved(
        int $ownerId,
        array $values,
        array $resolved,
    ): void {
        $this->connection->execute(
            $this->dialect->queryDeletePendingForOwner(),
            [$ownerId],
        );
        $pending = [];

        foreach ($values as $name => $attributeValues) {
            foreach ($attributeValues as $value) {
                $normalized = Dn::normalizedOrNull($value);

                if ($normalized !== null && isset($resolved[$normalized])) {
                    continue;
                }

                $pending[] = [
                    $name,
                    $normalized ?? strtolower($value),
                    $value,
                ];
            }
        }

        if ($pending === []) {
            return;
        }

        foreach (array_chunk($pending, self::LINKS_PER_STATEMENT) as $chunk) {
            $params = [];

            foreach ($chunk as [$name, $targetLcDn, $targetValue]) {
                $params[] = $ownerId;
                $params[] = $name;
                $params[] = $targetLcDn;
                $params[] = $targetValue;
                $params[] = '';
            }

            $this->connection->execute(
                $this->dialect->queryInsertPending(count($chunk)),
                $params,
            );
        }
    }

    /**
     * The id the DN is stored under, or null when nothing is stored there.
     */
    private function idOf(Dn $owner): ?int
    {
        foreach ($this->rowsOf($this->dialect->queryResolveDns(1), [$owner->normalizedString()]) as $row) {
            return $this->intColumn($row['entry_id'] ?? null);
        }

        return null;
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
