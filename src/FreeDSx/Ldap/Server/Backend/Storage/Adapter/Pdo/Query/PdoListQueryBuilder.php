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

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SortKeySpec;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;

use function array_merge;
use function implode;

/**
 * Builds the SQL query for PdoStorage::list().
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PdoListQueryBuilder
{
    public function __construct(
        private PdoDialectInterface $dialect,
    ) {}

    public function build(ListQuerySpec $spec): SqlQuery
    {
        $streamed = $this->tryBuildStreamingQuery($spec);

        if ($streamed !== null) {
            return $streamed;
        }

        $subentryCondition = $this->subentryCondition(
            $spec->subentries,
            'entry_id',
        );
        // Resuming an unsorted list seeks on the key directly; a sorted one seeks on the projected key, which only
        // exists once the sort has wrapped the query.
        $seek = $spec->after !== null && $spec->sortKeys === []
            ? new SqlQuery(
                'entry_id > ?',
                [$spec->after->entryKey],
            )
            : null;

        $query = match (true) {
            !$spec->subtree => $this->buildChildQuery(
                $spec->base,
                $spec->filter,
                $subentryCondition,
                $seek,
            ),
            $spec->base === '' => $this->buildRootQuery(
                $spec->filter,
                $subentryCondition,
                $seek,
            ),
            default => $this->buildSubtreeQuery(
                $spec->base,
                $spec->filter,
                $subentryCondition,
                $seek,
            ),
        };

        // A resumable walk needs one deterministic order, so an unsorted list gets the key order it seeks in.
        $query = $spec->sortKeys !== []
            ? $this->applySort($query, $spec->sortKeys)
            : $query->appending(' ORDER BY entry_id');

        // Bound rather than inlined: an inlined limit makes every distinct client size limit its own prepared statement.
        if ($spec->limit !== null) {
            $query = $query->appending(
                ' LIMIT ?',
                [$spec->limit],
            );
        }

        return $query;
    }

    /**
     * Bounds work to the spec's limit by pushing DISTINCT + subtree scope + LIMIT into the sidecar sub-select, wrapped
     * in a derived table (portable: MySQL/MariaDB reject LIMIT directly inside IN, and it still streams on SQLite).
     *
     * @param list<string> $filterParams
     */
    public function buildStreamingQuery(
        string $sidecarCondition,
        array $filterParams,
        ListQuerySpec $spec,
    ): SqlQuery {
        $fetchAll = $this->dialect->queryFetchAll();
        $params = $filterParams;
        $base = $spec->base;
        $after = $spec->after;

        // This shape exists to bound the candidate scan, so it is only ever built with a bound to spend.
        $limit = $spec->limit ?? throw new RuntimeException(
            'A streaming list query requires a row bound.',
        );

        // Applied inside the candidate select, since the limit below it would otherwise be spent on excluded rows.
        $subentryCondition = $this->subentryCondition(
            $spec->subentries,
            's.owner_entry_id',
        );
        $subentryClause = $subentryCondition !== null
            ? "AND $subentryCondition"
            : '';

        // Seeks and orders inside the candidate select as well, so the limit is spent on rows the caller has not seen.
        $seekClause = $after !== null
            ? 'AND s.owner_entry_id > ?'
            : '';

        if ($base === '') {
            $inner = <<<SQL
                SELECT DISTINCT s.owner_entry_id AS d FROM entry_attribute_values s
                    WHERE $sidecarCondition
                    $subentryClause
                    $seekClause
                    ORDER BY s.owner_entry_id
                    LIMIT ?
                SQL;
        } else {
            // Scope reads off entries, since the sidecar holds the key rather than the DN. The join is on the
            // entry key, so the limit still bounds the candidate scan.
            $inner = <<<SQL
                SELECT DISTINCT s.owner_entry_id AS d FROM entry_attribute_values s
                    INNER JOIN entries scope ON scope.entry_id = s.owner_entry_id
                    WHERE $sidecarCondition
                      AND (scope.lc_dn = ? OR scope.lc_dn LIKE ? ESCAPE '!')
                    $subentryClause
                    $seekClause
                    ORDER BY s.owner_entry_id
                    LIMIT ?
                SQL;
            $params[] = $base;
            $params[] = '%,' . SqlFilterUtility::escape($base);
        }

        if ($after !== null) {
            $params[] = $after->entryKey;
        }

        $params[] = $limit;

        return new SqlQuery(
            "$fetchAll WHERE entry_id IN (SELECT t.d FROM ($inner) t) ORDER BY entry_id",
            $params,
        );
    }

    /**
     * The streaming fast path, or null when it does not apply.
     *
     * A single drivable sidecar leaf under a bounded, unsorted subtree/root search drives off the sidecar index so the
     * limit short-circuits candidate scanning.
     */
    private function tryBuildStreamingQuery(ListQuerySpec $spec): ?SqlQuery
    {
        if (!$spec->subtree || $spec->limit === null || $spec->sortKeys !== []) {
            return null;
        }

        if ($spec->filter === null || $spec->filter->sidecarCondition === null) {
            return null;
        }

        return $this->buildStreamingQuery(
            $spec->filter->sidecarCondition,
            $spec->filter->params,
            $spec,
        );
    }

    private function buildChildQuery(
        string $base,
        ?SqlFilterResult $filterResult,
        ?string $subentryCondition,
        ?SqlQuery $seek,
    ): SqlQuery {
        $query = new SqlQuery(
            $this->dialect->queryFetchChildren(),
            [$base],
        );

        if ($filterResult !== null) {
            // short-circuits the child scan instead of an IN list materialising the whole match set (O(directory)).
            $filterSql = $filterResult->correlatedSql ?? $filterResult->sql;
            $query = $query->appending(
                ' AND (' . $filterSql . ')',
                $filterResult->params,
            );
        }

        if ($subentryCondition !== null) {
            $query = $query->appending(' AND ' . $subentryCondition);
        }

        return $this->appendSeek(
            $query,
            $seek,
            true,
        );
    }

    private function buildRootQuery(
        ?SqlFilterResult $filterResult,
        ?string $subentryCondition,
        ?SqlQuery $seek,
    ): SqlQuery {
        $conditions = [];
        $params = [];

        if ($filterResult !== null) {
            $conditions[] = '(' . $filterResult->sql . ')';
            $params = $filterResult->params;
        }

        if ($subentryCondition !== null) {
            $conditions[] = $subentryCondition;
        }

        if ($seek !== null) {
            $conditions[] = $seek->sql;
            $params = array_merge(
                $params,
                $seek->params,
            );
        }

        if ($conditions === []) {
            return new SqlQuery($this->dialect->queryFetchAll());
        }

        return new SqlQuery(
            $this->dialect->queryFetchAll() . ' WHERE ' . implode(' AND ', $conditions),
            $params,
        );
    }

    private function buildSubtreeQuery(
        string $base,
        ?SqlFilterResult $filterResult,
        ?string $subentryCondition,
        ?SqlQuery $seek,
    ): SqlQuery {
        if ($filterResult === null) {
            $query = new SqlQuery(
                $this->dialect->querySubtree(),
                [$base],
            );
            $hasWhere = $subentryCondition !== null;

            if ($subentryCondition !== null) {
                $query = $query->appending(' WHERE ' . $subentryCondition);
            }

            return $this->appendSeek(
                $query,
                $seek,
                $hasWhere,
            );
        }

        return $this->buildFilteredSubtreeQuery(
            $base,
            $filterResult,
            $subentryCondition,
            $seek,
        );
    }

    /**
     * Filter drives via the sidecar index; scope suffix is LIKE-checked per candidate.
     */
    private function buildFilteredSubtreeQuery(
        string $base,
        SqlFilterResult $filterResult,
        ?string $subentryCondition,
        ?SqlQuery $seek,
    ): SqlQuery {
        $fetchAll = $this->dialect->queryFetchAll();
        $filterSql = $filterResult->sql;
        $subentryClause = $subentryCondition !== null
            ? "AND $subentryCondition"
            : '';
        $sql = <<<SQL
            $fetchAll WHERE ($filterSql)
            AND (lc_dn = ? OR lc_dn LIKE ? ESCAPE '!')
            $subentryClause
            SQL;

        $params = $filterResult->params;
        $params[] = $base;
        $params[] = '%,' . SqlFilterUtility::escape($base);

        return $this->appendSeek(
            new SqlQuery(
                $sql,
                $params,
            ),
            $seek,
            true,
        );
    }

    /**
     * Appended last so its bindings follow every condition already in the query.
     */
    private function appendSeek(
        SqlQuery $query,
        ?SqlQuery $seek,
        bool $hasWhere,
    ): SqlQuery {
        if ($seek === null) {
            return $query;
        }

        return $query->appending(
            ($hasWhere ? ' AND ' : ' WHERE ') . $seek->sql,
            $seek->params,
        );
    }

    /**
     * The dialect condition for the given visibility, or null when both populations are selected.
     */
    private function subentryCondition(
        SubentryVisibility $subentries,
        string $dnColumn,
    ): ?string {
        return match ($subentries) {
            SubentryVisibility::All => null,
            SubentryVisibility::Hide => $this->dialect->querySubentryCondition($dnColumn, true),
            SubentryVisibility::Only => $this->dialect->querySubentryCondition($dnColumn, false),
        };
    }

    /**
     * @param list<SortKeySpec> $sortKeys
     */
    private function applySort(
        SqlQuery $query,
        array $sortKeys,
    ): SqlQuery {
        $sorted = $this->dialect->sortedQuery(
            $query->sql,
            $query->params,
            $sortKeys,
        );

        return new SqlQuery(
            $sorted->sql,
            $sorted->params,
        );
    }
}
