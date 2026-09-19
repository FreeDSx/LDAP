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
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\EntryRowCodec;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\EntryReader;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\SubtreeRename;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnTooLongException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\EntryAlreadyExistsException;
use PDOException;

/**
 * Writes entries and their index rows.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class EntryWriter
{
    /**
     * DNs per batched delete, well inside the placeholder limits of every supported driver.
     */
    private const DELETE_BATCH_SIZE = 500;

    public function __construct(
        private PdoConnection $connection,
        private PdoDialectInterface $dialect,
        private EntryReader $reader,
        private EntryIndexWriter $indexes,
        private EntryRowCodec $codec,
    ) {}

    /**
     * @throws EntryAlreadyExistsException when the DN is already taken
     * @throws DnTooLongException when the DN exceeds what the database can store
     */
    public function insert(Entry $entry): void
    {
        $normDn = $entry->getDn()->normalize();
        $dnString = $entry->getDn()->toString();
        $lcDn = $normDn->toString();

        $this->assertDnFits($dnString);
        $this->assertDnFits($lcDn);

        $this->connection->atomic(function () use ($entry, $lcDn, $dnString, $normDn): void {
            // The unique key on lc_dn is the arbiter, since a row lock on a DN that holds no row locks only the gap.
            $this->translatingRefusal(
                function () use ($lcDn, $dnString, $normDn, $entry): void {
                    $this->connection->execute($this->dialect->queryInsert(), [
                        $lcDn,
                        $dnString,
                        $normDn->getParent()?->toString() ?? '',
                        $this->codec->encode($entry),
                    ]);
                },
                $normDn,
            );

            $this->indexes->rewrite(
                $this->entryIdFor($normDn),
                $entry,
            );
        });
    }

    /**
     * @throws DnTooLongException when the DN exceeds what the database can store
     */
    public function store(
        Entry $entry,
        bool $rebuildIndexes = false,
    ): void {
        $normDn = $entry->getDn()->normalize();
        $dnString = $entry->getDn()->toString();
        $lcDn = $normDn->toString();

        // Both are stored, and normalising re-escapes, so the canonical form is not always the shorter of the two.
        $this->assertDnFits($dnString);
        $this->assertDnFits($lcDn);

        $this->connection->atomic(function () use ($entry, $lcDn, $dnString, $normDn, $rebuildIndexes): void {
            // Read the row we are about to overwrite under its write lock, so the diff is against what is actually
            // stored; a second writer then repairs whatever the first left behind instead of drifting from it.
            $current = $rebuildIndexes
                ? null
                : $this->lockedEntry($normDn);

            $this->connection->execute($this->dialect->queryUpsert(), [
                $lcDn,
                $dnString,
                $normDn->getParent()?->toString() ?? '',
                $this->codec->encode($entry),
            ]);

            // Neither dialect reports the key from an upsert, so it is read back before the index rows are written.
            $entryId = $this->entryIdFor($normDn);

            if ($current === null) {
                $this->indexes->rewrite($entryId, $entry);

                return;
            }

            $this->indexes->update(
                $entryId,
                $entry,
                $current,
            );
        });
    }

    /**
     * Re-keys the subtree without touching a single sidecar row, since those hang off entry_id rather than the DN.
     *
     * @throws EntryAlreadyExistsException when the new DN is already taken
     * @throws DnTooLongException when a resulting DN exceeds what the database can store
     */
    public function renameSubtree(
        Dn $from,
        Dn $to,
    ): void {
        $this->assertDnFits($to->toString());
        $this->assertDnFits($to->normalize()->toString());

        $this->connection->atomic(function () use ($from, $to): void {
            // Locked before the walk reads it, so a concurrent rename of the same base cannot interleave with this one.
            $base = $this->lockedEntry($from->normalize());

            if ($base === null) {
                return;
            }

            $rename = new SubtreeRename(
                $from,
                $to,
                $base->getDn()->toString(),
            );

            $this->translatingRefusal(function () use ($rename): void {
                $this->connection->execute(
                    $this->dialect->queryRenameDescendants(),
                    $this->renameDescendantParams($rename),
                );
            });

            $this->translatingRefusal(
                function () use ($rename, $to): void {
                    $this->connection->execute($this->dialect->queryRenameEntry(), [
                        $rename->toDisplay,
                        $rename->lcTo,
                        $to->normalize()->getParent()?->toString() ?? '',
                        $rename->lcFrom,
                    ]);
                },
                $to->normalize(),
            );
        });
    }

    public function remove(Dn $dn): void
    {
        $this->connection->execute(
            $this->dialect->queryDelete(),
            [$dn->normalize()->toString()],
        );
    }

    /**
     * Chunked so the placeholder count stays inside driver limits and full chunks share one prepared statement.
     *
     * @param list<Dn> $dns
     */
    public function removeAll(array $dns): void
    {
        $this->connection->joinAtomic(function () use ($dns): void {
            foreach (array_chunk($dns, self::DELETE_BATCH_SIZE) as $chunk) {
                $this->connection->execute(
                    $this->dialect->queryDeleteIn(count($chunk)),
                    array_map(
                        static fn(Dn $dn): string => $dn->normalize()->toString(),
                        $chunk,
                    ),
                );
            }
        });
    }

    public function lockForWrite(Dn $dn): void
    {
        $this->dialect->lockRowForWrite(
            $this->connection->pdo(),
            'entries',
            'lc_dn',
            $dn->normalize()->toString(),
        );
    }

    public function lockForReference(Dn $dn): bool
    {
        return $this->dialect->lockRowForReference(
            $this->connection->pdo(),
            'entries',
            'lc_dn',
            $dn->normalize()->toString(),
        );
    }

    /**
     * Runs a write, turning the driver failures the dialect recognises into the directory conditions they mean.
     *
     * @param Closure(): void $write
     * @param ?Dn $landsOn The DN written, where the write lands on exactly one.
     * @throws EntryAlreadyExistsException
     * @throws DnTooLongException
     */
    private function translatingRefusal(
        Closure $write,
        ?Dn $landsOn = null,
    ): void {
        try {
            $write();
        } catch (PDOException $e) {
            if ($landsOn !== null && $this->dialect->isDuplicateEntry($e)) {
                throw new EntryAlreadyExistsException(
                    sprintf('Entry already exists: %s', $landsOn->toString()),
                    previous: $e,
                );
            }
            if ($this->dialect->isValueTooLong($e)) {
                throw new DnTooLongException(
                    sprintf(
                        'The resulting DN exceeds the storage backend limit of %d bytes.',
                        $this->dialect->maxDnLength() ?? 0,
                    ),
                    previous: $e,
                );
            }

            throw $e;
        }
    }

    /**
     * The stored entry, locked for the rest of this transaction, or null when there is none.
     */
    private function lockedEntry(Dn $normDn): ?Entry
    {
        $this->lockForWrite($normDn);

        return $this->reader->find($normDn);
    }

    /**
     * The DN lengths are counted in characters, matching what the dialect's SUBSTR and length functions slice on.
     *
     * @return list<string|int>
     */
    private function renameDescendantParams(SubtreeRename $rename): array
    {
        $storedLength = mb_strlen($rename->fromDisplay, 'UTF-8');
        $canonicalLength = mb_strlen($rename->lcFrom, 'UTF-8');

        return [
            $storedLength,
            $rename->fromDisplay,
            $storedLength,
            $rename->toDisplay,
            $canonicalLength,
            $rename->lcTo,
            $canonicalLength,
            $rename->lcTo,
            $canonicalLength,
            $rename->lcTo,
            $rename->lcFrom,
        ];
    }

    /**
     * @throws RuntimeException when the row was written in this transaction but cannot be read back
     */
    private function entryIdFor(Dn $normDn): int
    {
        $row = $this->connection
            ->execute(
                $this->dialect->queryEntryId(),
                [$normDn->toString()],
            )
            ->fetch();

        if (!is_array($row) || !is_numeric($row['entry_id'] ?? null)) {
            throw new RuntimeException(sprintf(
                'The entry "%s" has no storage key.',
                $normDn->toString(),
            ));
        }

        return (int) $row['entry_id'];
    }

    /**
     * @throws DnTooLongException when the DN exceeds the dialect's maximum supported length
     */
    private function assertDnFits(string $dn): void
    {
        $max = $this->dialect->maxDnLength();
        if ($max === null) {
            return;
        }

        $length = strlen($dn);
        if ($length <= $max) {
            return;
        }

        throw new DnTooLongException(
            sprintf(
                'DN length %d exceeds the storage backend limit of %d bytes.',
                $length,
                $max,
            ),
        );
    }
}
