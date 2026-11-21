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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer;

use Closure;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoDeferredLinkDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoColumnCastTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\DeferredLinksInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;

use function array_chunk;
use function array_filter;
use function array_keys;
use function array_pop;
use function array_slice;
use function array_sum;
use function array_values;
use function count;
use function is_array;
use function sprintf;
use function strtolower;

/**
 * Holds an entry's linked values back from its write in a table of their own, then links them once asked to.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class DeferredLinkWriter implements DeferredLinksInterface
{
    use PdoColumnCastTrait;

    /**
     * Held back values per statement. Three placeholders each, inside the 999 bound older SQLite builds compile in.
     */
    private const VALUES_PER_STATEMENT = 300;

    /**
     * Entries linked per call at most, which lets a caller commit each batch on its own.
     */
    private const OWNERS_PER_BATCH = 500;

    /**
     * Held back values linked per call at most, unless the first entry of the batch holds more on its own.
     */
    private const VALUES_PER_BATCH = 5_000;

    public function __construct(
        private PdoDeferredLinkDialectInterface $dialect,
        private PdoConnection $connection,
        private LinkedAttributes $linked,
        private EntryLinkWriter $links,
        private int $valuesPerBatch = self::VALUES_PER_BATCH,
        private int $ownersPerBatch = self::OWNERS_PER_BATCH,
    ) {}

    public function deferLinks(
        string $uuid,
        Entry $entry,
        Closure $write,
    ): void {
        $values = array_filter(
            $this->linked->isEmpty() ? [] : $this->linked->valuesOf($entry),
            static fn(array $attributeValues): bool => $attributeValues !== [],
        );

        // An entry linking nothing names no entry that has yet to be placed.
        if ($values === []) {
            $write(
                $entry,
                new LinkDelta(),
            );
            $this->forget($uuid);

            return;
        }

        $write(
            $this->withoutLinks($entry),
            LinkDelta::untouched(),
        );
        $this->hold(
            $this->ownerIdOf(
                $uuid,
                $entry->getDn(),
            ),
            $values,
        );
    }

    public function linkDeferred(): bool
    {
        $owners = $this->nextOwners();

        if ($owners === []) {
            return false;
        }

        foreach ($owners as $ownerId) {
            $this->links->restate(
                $ownerId,
                $this->heldFor($ownerId),
            );
        }
        $this->connection->execute(
            $this->dialect->queryDeleteDeferredForOwners(count($owners)),
            $owners,
        );

        return true;
    }

    /**
     * Replaces what the entry held back before, since each write restates all of its linked values.
     *
     * @param array<string, list<string>> $values
     */
    private function hold(
        int $ownerId,
        array $values,
    ): void {
        $this->connection->execute(
            $this->dialect->queryDeleteDeferredForOwner(),
            [$ownerId],
        );
        $this->insertHeld(
            $ownerId,
            $values,
        );
    }

    /**
     * @param array<string, list<string>> $values
     */
    private function insertHeld(
        int $ownerId,
        array $values,
    ): void {
        $rows = [];

        foreach ($values as $name => $attributeValues) {
            foreach ($attributeValues as $value) {
                $rows[] = [
                    $name,
                    $value,
                ];
            }
        }

        foreach (array_chunk($rows, self::VALUES_PER_STATEMENT) as $chunk) {
            $params = [];

            foreach ($chunk as [$name, $value]) {
                $params[] = $ownerId;
                $params[] = $name;
                $params[] = $value;
            }

            $this->connection->execute(
                $this->dialect->queryInsertDeferred(count($chunk)),
                $params,
            );
        }
    }

    /**
     * @throws RuntimeException when the write left no entry holding the entryUUID
     */
    private function ownerIdOf(
        string $uuid,
        Dn $dn,
    ): int {
        return $this->connection
            ->execute(
                $this->dialect->queryEntryIdByUuid(),
                [strtolower($uuid)],
            )
            ->fetchIntColumn() ?? throw new RuntimeException(sprintf(
                'The entry "%s" has no storage key.',
                $dn->toString(),
            ));
    }

    private function forget(string $uuid): void
    {
        $this->connection->execute(
            $this->dialect->queryDeleteDeferredForEntryUuid(),
            [strtolower($uuid)],
        );
    }

    /**
     * The next entries to link, holding no more values than the batch's cap together, or one holding more alone.
     *
     * @return list<int>
     */
    private function nextOwners(): array
    {
        $counts = $this->heldCounts();
        $owners = array_keys($counts);

        // The last entry read may hold values past the read limit and waits for the next batch.
        if (count($owners) > 1 && array_sum($counts) > $this->valuesPerBatch) {
            array_pop($owners);
        }

        return array_slice(
            $owners,
            0,
            $this->ownersPerBatch,
        );
    }

    /**
     * How many of the next held back values each entry holds, reading one value past the batch's cap.
     *
     * @return array<int, int>
     */
    private function heldCounts(): array
    {
        $statement = $this->connection->execute(
            $this->dialect->queryDeferredOwners(),
            [$this->valuesPerBatch + 1],
        );
        $counts = [];

        while (($row = $statement->fetch()) !== false) {
            if (!is_array($row)) {
                continue;
            }
            $ownerId = $this->intColumn($row['owner_entry_id'] ?? null);

            $counts[$ownerId] = $this->intColumn($row['held'] ?? null);
        }

        return $counts;
    }

    /**
     * The values held back for the owner, keyed by lowercased attribute name.
     *
     * @return array<string, list<string>>
     */
    private function heldFor(int $ownerId): array
    {
        $statement = $this->connection->execute(
            $this->dialect->queryDeferredForOwner(),
            [$ownerId],
        );
        $values = [];

        while (($row = $statement->fetch()) !== false) {
            if (!is_array($row)) {
                continue;
            }
            $name = $this->stringColumn($row['attr_name_lower'] ?? null);

            $values[$name][] = $this->stringColumn($row['target_value'] ?? null);
        }

        return $values;
    }

    private function withoutLinks(Entry $entry): Entry
    {
        return new Entry(
            $entry->getDn(),
            ...array_values(array_filter(
                $entry->getAttributes(),
                fn(Attribute $attribute): bool => !$this->linked->links($attribute),
            )),
        );
    }
}
