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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SortKeySpec;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnectionProviderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\EntryIndexWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\ListQuerySpec;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\PdoListQueryBuilder;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\SqlQuery;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SidecarLeaf;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\SubtreeRename;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContextInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnTooLongException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\RowLockableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
use FreeDSx\Ldap\Server\Backend\Storage\FetchedBatch;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use Generator;
use PDO;

/**
 * PDO-backed storage; the container builds it from a PdoConfig set via ServerOptions::setStorageConfig().
 *
 * When injecting a pre-built PDO, wrap it in SharedPdoConnectionProvider and call PdoStorage::initialize($pdo, $dialect) first.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PdoStorage implements EntryStorageInterface, ResettableInterface, ChangeJournalingInterface, RowLockableInterface
{
    use ChangeJournalingTrait;

    /**
     * The current schema revision shipped in resources/pdo-schema.
     */
    public const SCHEMA_VERSION = 1;

    /**
     * Match ceiling for a composed AND's drivable leaf: below it the leaf is a cheap, complete driver via a near-free probe.
     */
    private const COMPOSED_DRIVER_PROBE_LIMIT = 128;

    /**
     * DNs per batched delete, well inside the placeholder limits of every supported driver.
     */
    private const DELETE_BATCH_SIZE = 500;

    /**
     * Rows a single list statement may transfer before the walk seeks on and issues the next one.
     */
    private const FETCH_BATCH_SIZE = 1000;

    private readonly PdoListQueryBuilder $queryBuilder;

    private readonly PdoTransactor $transactor;

    private readonly PdoStatementPool $statements;

    /**
     * @param EntryIndexWriter $indexes Must share $statements, so the two see one connection and one cache.
     * @param ?PdoStatementPool $statements Must draw from $provider; defaults to a pool of its own over that connection.
     * @param ?PdoTransactor $transactor Must draw from $provider; defaults to one of its own over that connection.
     * @param ?ChangeJournalInterface $journal Must share $transactor so an append joins the write it belongs to.
     */
    public function __construct(
        private readonly PdoConnectionProviderInterface $provider,
        private readonly FilterTranslatorInterface $translator,
        private readonly PdoDialectInterface $dialect,
        private readonly AttributeContextInterface $attributeContext,
        private readonly EntryIndexWriter $indexes,
        ?PdoStatementPool $statements = null,
        ?PdoTransactor $transactor = null,
        ?ChangeJournalInterface $journal = null,
    ) {
        if (!extension_loaded('mbstring')) {
            throw new RuntimeException(
                'The PDO storage backend requires the "mbstring" extension.',
            );
        }

        $this->queryBuilder = new PdoListQueryBuilder($dialect);
        $this->transactor = $transactor ?? new PdoTransactor(
            $provider,
            $dialect,
            new BlockingSleeper(),
        );
        $this->statements = $statements ?? new PdoStatementPool($provider);
        $this->journal = $journal;
    }

    public function reset(): void
    {
        $this->provider->reset();
        $this->statements->reset();
    }

    public static function initialize(
        PDO $pdo,
        PdoDialectInterface $dialect,
        ?SubstringIndexInterface $substringIndex = null,
    ): void {
        $pdo->setAttribute(
            PDO::ATTR_ERRMODE,
            PDO::ERRMODE_EXCEPTION,
        );
        $pdo->setAttribute(
            PDO::ATTR_DEFAULT_FETCH_MODE,
            PDO::FETCH_ASSOC,
        );

        $statements = [
            ...$dialect->schemaStatements(),
            ...($substringIndex?->schemaStatements($dialect) ?? []),
        ];

        foreach ($statements as $statement) {
            $pdo->exec($statement);
        }

        self::stampSchemaVersion($pdo);
    }

    /**
     * The full schema for a dialect as a runnable SQL script, to export to a file or feed to a migration tool.
     */
    public static function schemaDdl(PdoDialectInterface $dialect): string
    {
        return $dialect->schemaSql();
    }

    public function find(Dn $dn): ?Entry
    {
        $stmt = $this->statements->execute(
            $this->dialect->queryFetchEntry(),
            [$dn->normalize()->toString()],
        );
        $row = $stmt->fetch();

        return $row !== false
            ? $this->rowToEntry($row)
            : null;
    }

    public function exists(Dn $dn): bool
    {
        $stmt = $this->statements->execute(
            $this->dialect->queryExists(),
            [$dn->normalize()->toString()],
        );

        return $stmt->fetch() !== false;
    }

    public function list(StorageListOptions $options): EntryStream
    {
        $deadline = $options->timeLimit > 0
            ? microtime(true) + $options->timeLimit
            : null;

        $filterResult = $this->translator->translate($options->filter);

        // A composed filter with a selective drivable leaf streams off that leaf; PHP re-evaluates the full filter.
        $composed = $this->tryComposedStreamingQuery($filterResult, $options);
        if ($composed !== null) {
            return new EntryStream(
                $this->generateBatches(
                    $composed,
                    $deadline,
                    $options,
                    self::COMPOSED_DRIVER_PROBE_LIMIT,
                ),
                false,
            );
        }

        $isPreFiltered = $filterResult !== null && $filterResult->isExact;
        $maxRows = $this->maxRowsFor($options, $isPreFiltered);
        $batchSize = $maxRows === null
            ? self::FETCH_BATCH_SIZE
            : min($maxRows, self::FETCH_BATCH_SIZE);
        $spec = ListQuerySpec::fromOptions(
            $options,
            $filterResult,
            $batchSize,
            $this->sortSpecs($options),
        );

        return new EntryStream(
            $this->generateBatches(
                $this->queryBuilder->build($spec),
                $deadline,
                $options,
                $batchSize,
                $spec,
                $maxRows,
            ),
            $isPreFiltered,
        );
    }

    public function store(
        Entry $entry,
        bool $rebuildIndexes = false,
    ): void {
        $normDn = $entry->getDn()->normalize();
        $dnString = $entry->getDn()->toString();

        $this->assertDnFits($dnString);

        $lcDn = $normDn->toString();

        $this->atomic(function () use ($entry, $lcDn, $dnString, $normDn, $rebuildIndexes): void {
            // Read the row we are about to overwrite under its write lock, so the diff is against what is actually
            // stored; a second writer then repairs whatever the first left behind instead of drifting from it.
            $current = $rebuildIndexes
                ? null
                : $this->lockedEntry($normDn);

            $this->statements->execute($this->dialect->queryUpsert(), [
                $lcDn,
                $dnString,
                $normDn->getParent()?->toString() ?? '',
                $this->encodeAttributes($entry),
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
     */
    public function renameSubtree(
        Dn $from,
        Dn $to,
    ): void {
        $this->assertDnFits($to->toString());

        $this->atomic(function () use ($from, $to): void {
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

            $this->statements->execute(
                $this->dialect->queryRenameDescendants(),
                $this->renameDescendantParams($rename),
            );

            $this->statements->execute($this->dialect->queryRenameEntry(), [
                $rename->toDisplay,
                $rename->lcTo,
                $to->normalize()->getParent()?->toString() ?? '',
                $rename->lcFrom,
            ]);
        });
    }

    public function remove(Dn $dn): void
    {
        $this->statements->execute(
            $this->dialect->queryDelete(),
            [$dn->normalize()->toString()],
        );
    }

    /**
     * Chunked so the placeholder count stays inside driver limits and full chunks share one prepared statement.
     */
    public function removeAll(array $dns): void
    {
        $this->transactor->joinAtomic(function () use ($dns): void {
            foreach (array_chunk($dns, self::DELETE_BATCH_SIZE) as $chunk) {
                $this->statements->execute(
                    $this->dialect->queryDeleteIn(count($chunk)),
                    array_map(
                        static fn(Dn $dn): string => $dn->normalize()->toString(),
                        $chunk,
                    ),
                );
            }
        });
    }

    public function hasChildren(Dn $dn): bool
    {
        $stmt = $this->statements->execute(
            $this->dialect->queryHasChildren(),
            [$dn->normalize()->toString()],
        );

        return $stmt->fetch() !== false;
    }

    public function namingContexts(): array
    {
        $stmt = $this->statements->execute($this->dialect->queryNamingContexts());

        $contexts = [];
        while (($row = $stmt->fetch()) !== false) {
            if (!is_array($row) || !isset($row['dn']) || !is_string($row['dn'])) {
                continue;
            }
            $contexts[] = (new Dn($row['dn']))->normalize();
        }

        return $contexts;
    }

    public function atomic(callable $operation): void
    {
        $this->transactor->atomic($operation);
    }

    public function lockForWrite(Dn $dn): void
    {
        $this->dialect->lockRowForWrite(
            $this->transactor->pdo(),
            'entries',
            'lc_dn',
            $dn->normalize()->toString(),
        );
    }

    /**
     * Rows worth reading at all, or null to walk the whole result.
     *
     * An exact filter makes the client size limit a real ceiling on the answer.
     */
    private function maxRowsFor(
        StorageListOptions $options,
        bool $isPreFiltered,
    ): ?int {
        $ceiling = match (true) {
            $isPreFiltered => $options->sizeLimit > 0
                ? $options->sizeLimit
                : null,
            $options->lookthroughLimit > 0 => $options->lookthroughLimit + 1,
            default => null,
        };

        if ($options->maxCandidates === null) {
            return $ceiling;
        }

        // One past what a slice will hand over, so it can say whether more remain without the caller reading on.
        $sliceRead = $options->maxCandidates + 1;

        return $ceiling === null
            ? $sliceRead
            : min($ceiling, $sliceRead);
    }

    /**
     * Records the schema the tables were created from, so a database states which revision it holds.
     */
    private static function stampSchemaVersion(PDO $pdo): void
    {
        $statement = $pdo->prepare(<<<SQL
            INSERT INTO ldap_schema_version (id, version)
            SELECT 1, ?
            WHERE NOT EXISTS (SELECT 1 FROM ldap_schema_version WHERE id = 1)
            SQL);
        $statement->execute([self::SCHEMA_VERSION]);
    }

    /**
     * Drives a composed AND off its most selective drivable leaf, or null when the fast path does not apply.
     */
    private function tryComposedStreamingQuery(
        ?SqlFilterResult $filterResult,
        StorageListOptions $options,
    ): ?SqlQuery {
        if ($filterResult === null || $filterResult->drivableLeaves === []) {
            return null;
        }

        if (!$options->subtree || $options->sortKeys !== []) {
            return null;
        }

        $driver = $this->selectDriverLeaf($filterResult->drivableLeaves);

        if ($driver === null) {
            return null;
        }

        // The leaf was chosen for matching fewer rows than the probe cap, so this bound cannot truncate it.
        return $this->queryBuilder->buildStreamingQuery(
            $driver->condition,
            $driver->params,
            ListQuerySpec::fromOptions(
                $options,
                $filterResult,
                self::COMPOSED_DRIVER_PROBE_LIMIT,
                [],
            ),
        );
    }

    /**
     * The drivable leaf with the fewest matches under the probe cap, or null when every leaf is broader than the cap.
     *
     * @param list<SidecarLeaf> $leaves
     */
    private function selectDriverLeaf(array $leaves): ?SidecarLeaf
    {
        $best = null;
        $bestCount = self::COMPOSED_DRIVER_PROBE_LIMIT;

        foreach ($leaves as $leaf) {
            $count = $this->probeLeafSelectivity($leaf);

            if ($count < $bestCount) {
                $best = $leaf;
                $bestCount = $count;
            }

            if ($bestCount === 0) {
                break;
            }
        }

        return $best;
    }

    /**
     * Counts a leaf's matches up to the probe cap via a near-free bounded index scan.
     */
    private function probeLeafSelectivity(SidecarLeaf $leaf): int
    {
        $limit = self::COMPOSED_DRIVER_PROBE_LIMIT;
        $sql = <<<SQL
            SELECT COUNT(*) AS c FROM (
                SELECT 1 FROM entry_attribute_values s WHERE {$leaf->condition} LIMIT {$limit}
            ) probe
            SQL;

        $row = $this->statements->execute($sql, $leaf->params)->fetch();
        $count = is_array($row)
            ? ($row['c'] ?? 0)
            : 0;

        return is_numeric($count)
            ? (int) $count
            : 0;
    }

    /**
     * @return list<SortKeySpec>
     */
    private function sortSpecs(StorageListOptions $options): array
    {
        return array_values(array_map(
            fn(SortKey $sortKey): SortKeySpec => new SortKeySpec(
                strtolower($sortKey->getAttribute()),
                $sortKey->getUseReverseOrder() ? 'DESC' : 'ASC',
                $this->attributeContext->sortsNumerically(
                    $sortKey->getAttribute(),
                    $sortKey->getOrderingRule(),
                ),
            ),
            $options->sortKeys,
        ));
    }

    /**
     * Walks the result in bounded batches, seeking past the last row read rather than holding one cursor open.
     *
     * @return Generator<int, Entry, mixed, FetchedBatch>
     */
    private function generateBatches(
        SqlQuery $query,
        ?float $deadline,
        StorageListOptions $options,
        int $batchSize,
        ?ListQuerySpec $spec = null,
        ?int $maxRows = null,
    ): Generator {
        $allowed = $options->attributes === null
            ? null
            : array_fill_keys($options->attributes, true);
        $cursor = $options->after;
        $read = 0;

        // A sort orders by something the key says nothing about, so its walk resumes by count rather than by key.
        $isSorted = $options->sortKeys !== [];
        $delivered = $isSorted
            ? $options->after->position ?? 0
            : 0;

        while (true) {
            $remaining = $options->maxCandidates === null
                ? null
                : $options->maxCandidates - $read;
            $batch = yield from $this->generateBatch(
                $query,
                $deadline,
                $allowed,
                $remaining,
            );
            $read += $batch->rows;
            $delivered += $batch->rows;
            $cursor = $isSorted
                ? PageCursor::afterSorted($delivered)
                : $batch->cursor ?? $cursor;

            $isLast = $spec === null
                || $cursor === null
                || $batch->hasMore
                || $batch->rows < $batchSize
                || ($maxRows !== null && $read >= $maxRows);

            if ($isLast) {
                return new FetchedBatch(
                    $read,
                    $cursor,
                    $batch->hasMore,
                );
            }

            $query = $this->queryBuilder->build($spec->resumingAfter($cursor));
        }
    }

    /**
     * One statement's worth of rows, released as this returns so only one is ever open.
     *
     * @param array<string, true>|null $allowed
     * @return Generator<int, Entry, mixed, FetchedBatch>
     */
    private function generateBatch(
        SqlQuery $query,
        ?float $deadline,
        ?array $allowed,
        ?int $yieldCap = null,
    ): Generator {
        $stmt = $this->statements->execute(
            $query->sql,
            $query->params,
        );
        $rows = 0;
        $cursor = null;
        $hasMore = false;

        while (($row = $stmt->fetch()) !== false) {
            if ($deadline !== null && microtime(true) >= $deadline) {
                throw new TimeLimitExceededException();
            }

            // Read but not handed over: its only job is to prove the result did not end here.
            if ($yieldCap !== null && $rows >= $yieldCap) {
                $hasMore = true;

                break;
            }

            $rows++;
            $cursor = $this->cursorForRow($row) ?? $cursor;
            $entry = $this->rowToEntry(
                $row,
                $allowed,
            );

            if ($entry !== null) {
                yield $entry;
            }
        }

        return new FetchedBatch(
            $rows,
            $cursor,
            $hasMore,
        );
    }

    /**
     * The resume point a row represents, or null when the query did not project the key.
     */
    private function cursorForRow(mixed $row): ?PageCursor
    {
        if (!is_array($row)) {
            return null;
        }

        $key = $row['entry_id'] ?? null;

        return is_int($key) || is_string($key)
            ? PageCursor::afterEntry((int) $key)
            : null;
    }

    /**
     * The stored entry, locked for the rest of this transaction, or null when there is none.
     */
    private function lockedEntry(Dn $normDn): ?Entry
    {
        $this->dialect->lockRowForWrite(
            $this->transactor->pdo(),
            'entries',
            'lc_dn',
            $normDn->toString(),
        );

        return $this->find($normDn);
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
        $row = $this->statements
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

    private function encodeAttributes(Entry $entry): string
    {
        $attributes = [];

        foreach ($entry->getAttributes() as $attribute) {
            $attributes[$attribute->getDescription()] = array_values($attribute->getValues());
        }

        return serialize($attributes);
    }

    /**
     * @param array<string, true>|null $allowed Base names to materialize, or null for all.
     */
    private function rowToEntry(
        mixed $row,
        ?array $allowed = null,
    ): ?Entry {
        if (!is_array($row)) {
            return null;
        }

        $dn = isset($row['dn']) && is_string($row['dn'])
            ? $row['dn']
            : '';

        // A projection that materializes nothing, such as a 1.1 request, never reads the blob.
        if ($allowed === []) {
            return Entry::raw(
                new Dn($dn),
                [],
            );
        }

        $attributesBlob = isset($row['attributes']) && is_string($row['attributes'])
            ? $row['attributes']
            : 'a:0:{}';

        /** @var array<string, list<string>>|false $raw Trusted: written by encodeAttributes() from Attribute::getValues(): string[]. */
        $raw = @unserialize(
            $attributesBlob,
            ['allowed_classes' => false],
        );

        if (!is_array($raw)) {
            throw new StorageIoException('Failed to decode entry attributes; storage row is corrupted.');
        }

        $attributes = [];

        foreach ($raw as $name => $values) {
            if ($allowed !== null && !isset($allowed[Attribute::normalizeName($name)])) {
                continue;
            }

            $attributes[] = Attribute::fromArray(
                $name,
                $values,
            );
        }

        return Entry::raw(
            new Dn($dn),
            $attributes,
        );
    }
}
