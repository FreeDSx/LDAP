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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query;

use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SortKeySpec;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\EntryLinks;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\EntryRowCodec;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SidecarLeaf;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\FetchedBatch;
use FreeDSx\Ldap\Server\Backend\Storage\FetchedEntry;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContextInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\Search\Options\ReadBounds;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use Generator;

/**
 * Streams the entries a list request selects, in bounded batches that seek on rather than holding a cursor open.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class EntryLister implements ListEntryInterface
{
    /**
     * Match ceiling for a composed AND's drivable leaf: below it the leaf is a cheap, complete driver via a near-free probe.
     */
    private const COMPOSED_DRIVER_PROBE_LIMIT = 128;

    /**
     * Rows a single list statement may transfer before the walk seeks on and issues the next one.
     */
    private const FETCH_BATCH_SIZE = 1000;

    public function __construct(
        private PdoConnection $connection,
        private PdoListQueryBuilder $queryBuilder,
        private FilterTranslatorInterface $translator,
        private AttributeContextInterface $attributeContext,
        private EntryRowCodec $codec,
        private EntryLinks $links,
    ) {}

    public function list(StorageListOptions $options): EntryStream
    {
        $filterResult = $this->translator->translate($options->filter);

        // A composed filter with a selective drivable leaf streams off that leaf; PHP re-evaluates the full filter.
        $composed = $this->tryComposedStreamingQuery(
            $filterResult,
            $options,
        );
        if ($composed !== null) {
            return EntryStream::positioned(
                $this->generateSingleBatch(
                    $composed,
                    $options,
                ),
                false,
            );
        }

        return $this->keysetStream(
            $options,
            $filterResult,
        );
    }

    /**
     * The general walk: the translated filter as far as SQL can take it, seeking on by key or by sort position.
     */
    private function keysetStream(
        StorageListOptions $options,
        ?SqlFilterResult $filterResult,
    ): EntryStream {
        $maxRows = $this->maxRowsFor($options->bounds);
        $batchSize = $maxRows === null
            ? self::FETCH_BATCH_SIZE
            : min($maxRows, self::FETCH_BATCH_SIZE);
        $spec = ListQuerySpec::fromOptions(
            $options,
            $filterResult,
            $batchSize,
            $this->sortSpecs($options),
        );

        return EntryStream::positioned(
            $this->generateBatches(
                $this->queryBuilder->build($spec),
                $options,
                $batchSize,
                $spec,
                $maxRows,
            ),
            $filterResult !== null && $filterResult->isExact,
        );
    }

    /**
     * Rows worth reading at all, or null to walk the whole result.
     */
    private function maxRowsFor(ReadBounds $bounds): ?int
    {
        $ceiling = $bounds->lookthroughLimit > 0
            ? $bounds->lookthroughLimit + 1
            : null;

        $limit = $bounds->limit();
        if ($limit === null) {
            return $ceiling;
        }

        // One past what a slice will hand over, so it can say whether more remain without the caller reading on.
        $sliceRead = $limit + 1;

        return $ceiling === null
            ? $sliceRead
            : min($ceiling, $sliceRead);
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

        if (!$options->scope->subtree || $options->sortKeys !== []) {
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

        $row = $this->connection
            ->execute(
                $sql,
                $leaf->params,
            )
            ->fetch();
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
     * A query that is never resumed, such as the drive off a composed AND's leaf, read as one statement.
     *
     * @return Generator<int, FetchedEntry, mixed, FetchedBatch>
     */
    private function generateSingleBatch(
        SqlQuery $query,
        StorageListOptions $options,
    ): Generator {
        $batch = yield from $this->generateBatch(
            $query,
            $options->bounds->deadline,
            $options->projection,
            $options->bounds->limit(),
        );

        return new FetchedBatch(
            $batch->rows,
            $batch->cursor ?? $options->bounds->resumeAfter(),
            $batch->hasMore,
        );
    }

    /**
     * Walks the result in bounded batches, seeking past the last row read rather than holding one cursor open.
     *
     * @return Generator<int, FetchedEntry, mixed, FetchedBatch>
     */
    private function generateBatches(
        SqlQuery $query,
        StorageListOptions $options,
        int $batchSize,
        ListQuerySpec $spec,
        ?int $maxRows,
    ): Generator {
        $bounds = $options->bounds;
        $cursor = $bounds->resumeAfter();
        $read = 0;

        // A sort orders by something the key says nothing about, so its walk resumes by count rather than by key.
        $isSorted = $options->sortKeys !== [];
        $delivered = $isSorted
            ? $bounds->resumeAfter()->position ?? 0
            : 0;

        while (true) {
            $limit = $bounds->limit();
            $remaining = $limit === null
                ? null
                : $limit - $read;
            $batch = yield from $this->generateBatch(
                $query,
                $bounds->deadline,
                $options->projection,
                $remaining,
                $isSorted
                    ? $delivered
                    : null,
            );
            $read += $batch->rows;
            $delivered += $batch->rows;
            $cursor = $isSorted
                ? PageCursor::afterSorted($delivered)
                : $batch->cursor ?? $cursor;

            $pageIsFull = $batch->hasMore;
            $resultIsExhausted = $batch->rows < $batchSize;
            $ceilingIsReached = $maxRows !== null && $read >= $maxRows;

            if ($cursor === null || $pageIsFull || $resultIsExhausted || $ceilingIsReached) {
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
     * @param ?int $deliveredBefore Rows handed over prior to this batch.
     * @return Generator<int, FetchedEntry, mixed, FetchedBatch>
     */
    private function generateBatch(
        SqlQuery $query,
        ?float $deadline,
        EntryProjection $projection,
        ?int $yieldCap = null,
        ?int $deliveredBefore = null,
    ): Generator {
        $rows = new BatchedRows(
            $this->connection->execute(
                $query->sql,
                $query->params,
            ),
            $deadline,
            $yieldCap,
        );
        $allowed = $projection->allowed();

        // Reading runs ahead of handing over, so the cursor comes from the row being yielded, not the one just read.
        $cursor = null;
        $delivered = 0;

        foreach ($this->pairedWithLinks($rows, $projection) as [$row, $links]) {
            $delivered++;
            $cursor = $this->cursorForRow($row) ?? $cursor;

            if (!is_array($row)) {
                continue;
            }

            yield new FetchedEntry(
                $this->codec->decode(
                    $row,
                    $allowed,
                    $links,
                ),
                $deliveredBefore === null
                    ? $cursor
                    : PageCursor::afterSorted($deliveredBefore + $delivered),
            );
        }

        return new FetchedBatch(
            $rows->read(),
            $cursor,
            $rows->hasMore(),
        );
    }

    /**
     * Each row with the links it carries, or with none when this read does not pay for them.
     *
     * @param iterable<int, mixed> $rows
     * @return Generator<int, array{mixed, array<string, list<string>>}>
     */
    private function pairedWithLinks(
        iterable $rows,
        EntryProjection $projection,
    ): Generator {
        if ($this->links->hydrates($projection)) {
            yield from $this->links->hydrating(
                $rows,
                $projection,
            );

            return;
        }

        foreach ($rows as $row) {
            yield [$row, []];
        }
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
}
