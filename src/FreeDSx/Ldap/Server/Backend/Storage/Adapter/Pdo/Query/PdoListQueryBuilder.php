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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SortKeySpec;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;

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

    /**
     * @param list<SortKeySpec> $sortKeys
     */
    public function build(
        string $base,
        bool $subtree,
        ?SqlFilterResult $filterResult,
        ?int $sqlLimit,
        array $sortKeys,
        SubentryVisibility $subentries = SubentryVisibility::All,
    ): SqlQuery {
        $streamed = $this->tryBuildStreamingQuery(
            $base,
            $subtree,
            $filterResult,
            $sqlLimit,
            $sortKeys,
            $subentries,
        );

        if ($streamed !== null) {
            return $streamed;
        }

        $subentryCondition = $this->subentryCondition(
            $subentries,
            'entry_id',
        );
        $query = match (true) {
            !$subtree => $this->buildChildQuery(
                $base,
                $filterResult,
                $subentryCondition,
            ),
            $base === '' => $this->buildRootQuery(
                $filterResult,
                $subentryCondition,
            ),
            default => $this->buildSubtreeQuery(
                $base,
                $filterResult,
                $subentryCondition,
            ),
        };

        if ($sortKeys !== []) {
            $query = $this->applySort(
                $query,
                $sortKeys,
            );
        }

        // Bound rather than inlined: an inlined limit makes every distinct client size limit its own prepared statement.
        if ($sqlLimit !== null) {
            $query = $query->appending(
                ' LIMIT ?',
                [$sqlLimit],
            );
        }

        return $query;
    }

    /**
     * Bounds work to $sqlLimit by pushing DISTINCT + subtree scope + LIMIT into the sidecar sub-select, wrapped in a
     * derived table (portable: MySQL/MariaDB reject LIMIT directly inside IN, and it still streams on SQLite).
     *
     * @param list<string> $filterParams
     */
    public function buildStreamingQuery(
        string $sidecarCondition,
        array $filterParams,
        string $base,
        int $sqlLimit,
        SubentryVisibility $subentries = SubentryVisibility::All,
    ): SqlQuery {
        $fetchAll = $this->dialect->queryFetchAll();
        $params = $filterParams;

        // Applied inside the candidate select, since the limit below it would otherwise be spent on excluded rows.
        $subentryCondition = $this->subentryCondition(
            $subentries,
            's.owner_entry_id',
        );
        $subentryClause = $subentryCondition !== null
            ? "AND $subentryCondition"
            : '';

        if ($base === '') {
            $inner = <<<SQL
                SELECT DISTINCT s.owner_entry_id AS d FROM entry_attribute_values s
                    WHERE $sidecarCondition
                    $subentryClause
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
                    LIMIT ?
                SQL;
            $params[] = $base;
            $params[] = '%,' . SqlFilterUtility::escape($base);
        }

        $params[] = $sqlLimit;

        return new SqlQuery(
            "$fetchAll WHERE entry_id IN (SELECT t.d FROM ($inner) t)",
            $params,
        );
    }

    /**
     * The streaming fast path, or null when it does not apply.
     *
     * A single drivable sidecar leaf under a bounded, unsorted subtree/root search drives off the sidecar index so the
     * limit short-circuits candidate scanning.
     *
     * @param list<SortKeySpec> $sortKeys
     */
    private function tryBuildStreamingQuery(
        string $base,
        bool $subtree,
        ?SqlFilterResult $filterResult,
        ?int $sqlLimit,
        array $sortKeys,
        SubentryVisibility $subentries = SubentryVisibility::All,
    ): ?SqlQuery {
        if (!$subtree || $sqlLimit === null || $sortKeys !== []) {
            return null;
        }

        if ($filterResult === null || $filterResult->sidecarCondition === null) {
            return null;
        }

        return $this->buildStreamingQuery(
            $filterResult->sidecarCondition,
            $filterResult->params,
            $base,
            $sqlLimit,
            $subentries,
        );
    }

    private function buildChildQuery(
        string $base,
        ?SqlFilterResult $filterResult,
        ?string $subentryCondition,
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

        return $subentryCondition !== null
            ? $query->appending(' AND ' . $subentryCondition)
            : $query;
    }

    private function buildRootQuery(
        ?SqlFilterResult $filterResult,
        ?string $subentryCondition,
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
    ): SqlQuery {
        if ($filterResult === null) {
            $query = new SqlQuery(
                $this->dialect->querySubtree(),
                [$base],
            );

            return $subentryCondition !== null
                ? $query->appending(' WHERE ' . $subentryCondition)
                : $query;
        }

        return $this->buildFilteredSubtreeQuery(
            $base,
            $filterResult,
            $subentryCondition,
        );
    }

    /**
     * Filter drives via the sidecar index; scope suffix is LIKE-checked per candidate.
     */
    private function buildFilteredSubtreeQuery(
        string $base,
        SqlFilterResult $filterResult,
        ?string $subentryCondition,
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

        return new SqlQuery(
            $sql,
            $params,
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
