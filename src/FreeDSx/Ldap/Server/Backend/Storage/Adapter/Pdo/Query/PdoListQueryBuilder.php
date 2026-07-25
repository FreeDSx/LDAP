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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SortKeySpec;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;

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
     * @param SortKey[] $sortKeys
     */
    public function build(
        string $base,
        bool $subtree,
        ?SqlFilterResult $filterResult,
        ?int $sqlLimit,
        array $sortKeys,
    ): SqlQuery {
        $streamed = $this->tryBuildStreamingQuery(
            $base,
            $subtree,
            $filterResult,
            $sqlLimit,
            $sortKeys,
        );

        if ($streamed !== null) {
            return $streamed;
        }

        $query = match (true) {
            !$subtree => $this->buildChildQuery($base, $filterResult),
            $base === '' => $this->buildRootQuery($filterResult),
            default => $this->buildSubtreeQuery($base, $filterResult),
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
    ): SqlQuery {
        $fetchAll = $this->dialect->queryFetchAll();
        $params = $filterParams;

        if ($base === '') {
            $inner = <<<SQL
                SELECT DISTINCT s.entry_lc_dn AS d FROM entry_attribute_values s
                    WHERE $sidecarCondition
                    LIMIT ?
                SQL;
        } else {
            $inner = <<<SQL
                SELECT DISTINCT s.entry_lc_dn AS d FROM entry_attribute_values s
                    WHERE $sidecarCondition
                      AND (s.entry_lc_dn = ? OR s.entry_lc_dn LIKE ? ESCAPE '!')
                    LIMIT ?
                SQL;
            $params[] = $base;
            $params[] = '%,' . SqlFilterUtility::escape($base);
        }

        $params[] = $sqlLimit;

        return new SqlQuery(
            "$fetchAll WHERE lc_dn IN (SELECT t.d FROM ($inner) t)",
            $params,
        );
    }

    /**
     * The streaming fast path, or null when it does not apply.
     *
     * A single drivable sidecar leaf under a bounded, unsorted subtree/root search drives off the sidecar index so the
     * limit short-circuits candidate scanning.
     *
     * @param SortKey[] $sortKeys
     */
    private function tryBuildStreamingQuery(
        string $base,
        bool $subtree,
        ?SqlFilterResult $filterResult,
        ?int $sqlLimit,
        array $sortKeys,
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
        );
    }

    private function buildChildQuery(
        string $base,
        ?SqlFilterResult $filterResult,
    ): SqlQuery {
        $query = new SqlQuery(
            $this->dialect->queryFetchChildren(),
            [$base],
        );

        if ($filterResult === null) {
            return $query;
        }

        // short-circuits the child scan instead of an IN list materialising the whole match set (O(directory)).
        $filterSql = $filterResult->correlatedSql ?? $filterResult->sql;

        return $query->appending(
            ' AND (' . $filterSql . ')',
            $filterResult->params,
        );
    }

    private function buildRootQuery(?SqlFilterResult $filterResult): SqlQuery
    {
        if ($filterResult === null) {
            return new SqlQuery($this->dialect->queryFetchAll());
        }

        return new SqlQuery(
            $this->dialect->queryFetchAll() . ' WHERE (' . $filterResult->sql . ')',
            $filterResult->params,
        );
    }

    private function buildSubtreeQuery(
        string $base,
        ?SqlFilterResult $filterResult,
    ): SqlQuery {
        if ($filterResult === null) {
            return new SqlQuery(
                $this->dialect->querySubtree(),
                [$base],
            );
        }

        return $this->buildFilteredSubtreeQuery(
            $base,
            $filterResult,
        );
    }

    /**
     * Filter drives via the sidecar index; scope suffix is LIKE-checked per candidate.
     */
    private function buildFilteredSubtreeQuery(
        string $base,
        SqlFilterResult $filterResult,
    ): SqlQuery {
        $fetchAll = $this->dialect->queryFetchAll();
        $filterSql = $filterResult->sql;
        $sql = <<<SQL
            $fetchAll WHERE ($filterSql)
            AND (lc_dn = ? OR lc_dn LIKE ? ESCAPE '!')
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
     * @param SortKey[] $sortKeys
     */
    private function applySort(
        SqlQuery $query,
        array $sortKeys,
    ): SqlQuery {
        $specs = array_values(array_map(
            static fn(SortKey $sortKey): SortKeySpec => new SortKeySpec(
                strtolower($sortKey->getAttribute()),
                $sortKey->getUseReverseOrder() ? 'DESC' : 'ASC',
            ),
            $sortKeys,
        ));

        $sorted = $this->dialect->sortedQuery(
            $query->sql,
            $query->params,
            $specs,
        );

        return new SqlQuery(
            $sorted->sql,
            $sorted->params,
        );
    }
}
