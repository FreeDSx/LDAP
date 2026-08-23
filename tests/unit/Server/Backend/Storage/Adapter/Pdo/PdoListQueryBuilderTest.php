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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo;

use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\MysqlDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SortKeySpec;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\ListQuerySpec;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\PdoListQueryBuilder;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;
use PHPUnit\Framework\TestCase;

final class PdoListQueryBuilderTest extends TestCase
{
    public function test_no_sort_keys_orders_by_the_entry_key(): void
    {
        [$sql, $params] = $this->rootQuery(
            new PdoListQueryBuilder(new SqliteDialect()),
            null,
        );

        // A walk resumes by seeking on this key, so the order it seeks in has to be the order it reads in.
        self::assertStringEndsWith('ORDER BY entry_id', $sql);
        self::assertSame([], $params);
    }

    public function test_sqlite_ascending_orders_nulls_last_with_one_param(): void
    {
        [$sql, $params] = $this->rootQuery(
            new PdoListQueryBuilder(new SqliteDialect()),
            null,
            SortKey::ascending('CN'),
        );

        self::assertStringContainsString('ORDER BY', $sql);
        self::assertStringContainsString('ASC NULLS LAST', $sql);
        self::assertSame(['cn'], $params);
    }

    public function test_sqlite_orders_a_numeric_key_as_a_number(): void
    {
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(self::querySpec(
            sortKeys: [self::spec(SortKey::ascending('uidNumber'), numeric: true)],
        ));

        self::assertStringContainsString(
            'MIN(CAST(eav.value_lower AS INTEGER))',
            $query->sql,
        );
    }

    public function test_mysql_orders_a_numeric_key_as_a_number(): void
    {
        $query = (new PdoListQueryBuilder(new MysqlDialect()))->build(self::querySpec(
            sortKeys: [self::spec(SortKey::ascending('uidNumber'), numeric: true)],
        ));

        self::assertStringContainsString(
            'MIN(CAST(eav.value_lower AS SIGNED))',
            $query->sql,
        );
    }

    public function test_sqlite_descending_orders_nulls_first_with_one_param(): void
    {
        [$sql, $params] = $this->rootQuery(
            new PdoListQueryBuilder(new SqliteDialect()),
            null,
            SortKey::descending('cn'),
        );

        self::assertStringContainsString('DESC NULLS FIRST', $sql);
        self::assertSame(['cn'], $params);
    }

    public function test_mysql_ascending_projects_the_key_once_and_orders_nulls_last(): void
    {
        [$sql, $params] = $this->rootQuery(
            new PdoListQueryBuilder(new MysqlDialect()),
            null,
            SortKey::ascending('cn'),
        );

        self::assertStringContainsString('AS __sk0', $sql);
        self::assertStringContainsString('ORDER BY __sk0 IS NULL ASC, __sk0 ASC', $sql);
        self::assertSame(['cn'], $params);
    }

    public function test_mysql_descending_projects_the_key_once_and_orders_nulls_first(): void
    {
        [$sql, $params] = $this->rootQuery(
            new PdoListQueryBuilder(new MysqlDialect()),
            null,
            SortKey::descending('cn'),
        );

        self::assertStringContainsString('ORDER BY __sk0 IS NULL DESC, __sk0 DESC', $sql);
        self::assertSame(['cn'], $params);
    }

    public function test_mysql_multi_key_projects_each_key_and_orders_in_sequence(): void
    {
        [$sql, $params] = $this->rootQuery(
            new PdoListQueryBuilder(new MysqlDialect()),
            null,
            SortKey::ascending('sn'),
            SortKey::descending('cn'),
        );

        self::assertStringContainsString(
            'ORDER BY __sk0 IS NULL ASC, __sk0 ASC, __sk1 IS NULL DESC, __sk1 DESC',
            $sql,
        );
        self::assertSame(
            ['sn', 'cn'],
            $params,
        );
    }

    public function test_mysql_sort_params_bind_before_the_base_query_params(): void
    {
        [$sql, $params] = $this->rootQuery(
            new PdoListQueryBuilder(new MysqlDialect()),
            new SqlFilterResult('eav.value_lower = ?', ['smith']),
            SortKey::ascending('sn'),
        );

        // The projected sort key precedes the nested base query, so its param binds first.
        self::assertStringContainsString('FROM (', $sql);
        self::assertSame(
            ['sn', 'smith'],
            $params,
        );
    }

    public function test_filter_params_precede_sort_params(): void
    {
        [, $params] = $this->rootQuery(
            new PdoListQueryBuilder(new SqliteDialect()),
            new SqlFilterResult('eav.value_lower = ?', ['smith']),
            SortKey::ascending('sn'),
        );

        self::assertSame(
            ['smith', 'sn'],
            $params,
        );
    }

    public function test_streaming_subtree_pushes_limit_and_scope_into_the_sidecar_subquery(): void
    {
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(self::querySpec(
            base: 'ou=people,dc=foo,dc=bar',
            filter: $this->sidecarLeaf(),
            limit: 500,
        ));

        self::assertStringContainsString(
            'SELECT DISTINCT s.owner_entry_id AS d',
            $query->sql,
        );
        self::assertStringContainsString(
            "AND (scope.lc_dn = ? OR scope.lc_dn LIKE ? ESCAPE '!')",
            $query->sql,
        );
        self::assertStringContainsString(
            'IN (SELECT t.d FROM (',
            $query->sql,
        );
        self::assertStringContainsString(
            'LIMIT ?',
            $query->sql,
        );
        // Ordered inside the candidate select too, so the limit there is spent in the same order the walk resumes in.
        self::assertStringContainsString(
            'ORDER BY s.owner_entry_id',
            $query->sql,
        );
        self::assertSame(
            ['smith', 'ou=people,dc=foo,dc=bar', '%,ou=people,dc=foo,dc=bar', 500],
            $query->params,
        );
    }

    public function test_streaming_root_query_omits_the_subtree_scope(): void
    {
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(self::querySpec(
            filter: $this->sidecarLeaf(),
            limit: 500,
        ));

        self::assertStringContainsString(
            'IN (SELECT t.d FROM (',
            $query->sql,
        );
        self::assertStringNotContainsString(
            'scope.lc_dn = ?',
            $query->sql,
        );
        self::assertSame(
            ['smith', 500],
            $query->params,
        );
    }

    public function test_mysql_produces_the_same_streaming_shape(): void
    {
        $query = (new PdoListQueryBuilder(new MysqlDialect()))->build(self::querySpec(
            base: 'ou=people,dc=foo,dc=bar',
            filter: $this->sidecarLeaf(),
            limit: 500,
        ));

        self::assertStringContainsString(
            'SELECT DISTINCT s.owner_entry_id AS d',
            $query->sql,
        );
        self::assertStringContainsString(
            'IN (SELECT t.d FROM (',
            $query->sql,
        );
    }

    public function test_sort_keys_disable_the_streaming_fast_path(): void
    {
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(self::querySpec(
            base: 'ou=people,dc=foo,dc=bar',
            filter: $this->sidecarLeaf(),
            limit: 500,
            sortKeys: [self::spec(SortKey::ascending('cn'))],
        ));

        self::assertStringNotContainsString(
            'SELECT t.d FROM (',
            $query->sql,
        );
        self::assertStringContainsString(
            'ORDER BY',
            $query->sql,
        );
    }

    public function test_null_limit_disables_the_streaming_fast_path(): void
    {
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(self::querySpec(
            base: 'ou=people,dc=foo,dc=bar',
            filter: $this->sidecarLeaf(),
        ));

        self::assertStringNotContainsString(
            'SELECT t.d FROM (',
            $query->sql,
        );
    }

    public function test_absent_sidecar_condition_disables_the_streaming_fast_path(): void
    {
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(self::querySpec(
            base: 'ou=people,dc=foo,dc=bar',
            filter: new SqlFilterResult('(a) AND (b)', ['x', 'y']),
            limit: 500,
        ));

        self::assertStringNotContainsString(
            'SELECT t.d FROM (',
            $query->sql,
        );
        self::assertStringContainsString(
            ' LIMIT ?',
            $query->sql,
        );
        self::assertSame(
            ['x', 'y', 'ou=people,dc=foo,dc=bar', '%,ou=people,dc=foo,dc=bar', 500],
            $query->params,
        );
    }

    public function test_child_scope_disables_the_streaming_fast_path(): void
    {
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(self::querySpec(
            base: 'ou=people,dc=foo,dc=bar',
            subtree: false,
            filter: $this->sidecarLeaf(),
            limit: 500,
        ));

        self::assertStringNotContainsString(
            'SELECT t.d FROM (',
            $query->sql,
        );
    }

    public function test_child_scope_uses_the_correlated_exists_form(): void
    {
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(self::querySpec(
            base: 'ou=people,dc=foo,dc=bar',
            subtree: false,
            filter: $this->sidecarLeaf(),
            limit: 5001,
        ));

        self::assertStringContainsString(
            'lc_parent_dn = ?',
            $query->sql,
        );
        self::assertStringContainsString(
            'EXISTS (',
            $query->sql,
        );
        // The sidecar column is named apart from the outer one so this cannot bind to the inner scope.
        self::assertStringContainsString(
            's.owner_entry_id = entry_id',
            $query->sql,
        );
        self::assertStringNotContainsString(
            'entry_id IN (',
            $query->sql,
        );
    }

    public function test_child_scope_falls_back_to_the_in_form_without_a_correlated_form(): void
    {
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(self::querySpec(
            base: 'ou=people,dc=foo,dc=bar',
            subtree: false,
            filter: new SqlFilterResult(
                "entry_id IN (SELECT s.owner_entry_id FROM entry_attribute_values s WHERE s.attr_name_lower = 'cn')",
                [],
            ),
            limit: 5001,
        ));

        self::assertStringContainsString(
            'entry_id IN (',
            $query->sql,
        );
        self::assertStringNotContainsString(
            'EXISTS (',
            $query->sql,
        );
    }

    private function sidecarLeaf(): SqlFilterResult
    {
        return new SqlFilterResult(
            "entry_id IN (SELECT s.owner_entry_id FROM entry_attribute_values s WHERE s.attr_name_lower = 'cn' AND s.value_lower = ?)",
            ['smith'],
            sidecarCondition: "s.attr_name_lower = 'cn' AND s.value_lower = ?",
        );
    }

    /**
     * @return array{0: string, 1: list<string|int>}
     */
    private function rootQuery(
        PdoListQueryBuilder $builder,
        ?SqlFilterResult $filter,
        SortKey ...$sortKeys,
    ): array {
        $query = $builder->build(self::querySpec(
            filter: $filter,
            sortKeys: array_values(array_map(
                self::spec(...),
                $sortKeys,
            )),
        ));

        return [$query->sql, $query->params];
    }

    /**
     * @param list<SortKeySpec> $sortKeys
     */
    private static function querySpec(
        string $base = '',
        bool $subtree = true,
        ?SqlFilterResult $filter = null,
        ?int $limit = null,
        array $sortKeys = [],
    ): ListQuerySpec {
        return new ListQuerySpec(
            base: $base,
            subtree: $subtree,
            filter: $filter,
            limit: $limit,
            sortKeys: $sortKeys,
        );
    }

    private static function spec(
        SortKey $sortKey,
        bool $numeric = false,
    ): SortKeySpec {
        return new SortKeySpec(
            strtolower($sortKey->getAttribute()),
            $sortKey->getUseReverseOrder() ? 'DESC' : 'ASC',
            $numeric,
        );
    }
}
