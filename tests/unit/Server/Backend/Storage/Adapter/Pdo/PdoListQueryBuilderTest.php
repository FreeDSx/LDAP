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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\PdoListQueryBuilder;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;
use PHPUnit\Framework\TestCase;

final class PdoListQueryBuilderTest extends TestCase
{
    public function test_no_sort_keys_appends_no_order_by(): void
    {
        [$sql, $params] = $this->rootQuery(
            new PdoListQueryBuilder(new SqliteDialect()),
            null,
        );

        self::assertStringNotContainsString('ORDER BY', $sql);
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
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(
            '',
            true,
            null,
            null,
            [self::spec(SortKey::ascending('uidNumber'), numeric: true)],
        );

        self::assertStringContainsString(
            'MIN(CAST(eav.value_lower AS INTEGER))',
            $query->sql,
        );
    }

    public function test_mysql_orders_a_numeric_key_as_a_number(): void
    {
        $query = (new PdoListQueryBuilder(new MysqlDialect()))->build(
            '',
            true,
            null,
            null,
            [self::spec(SortKey::ascending('uidNumber'), numeric: true)],
        );

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
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(
            'ou=people,dc=foo,dc=bar',
            true,
            $this->sidecarLeaf(),
            500,
            [],
        );

        self::assertStringContainsString(
            'SELECT DISTINCT s.entry_lc_dn AS d',
            $query->sql,
        );
        self::assertStringContainsString(
            "AND (s.entry_lc_dn = ? OR s.entry_lc_dn LIKE ? ESCAPE '!')",
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
        self::assertStringNotContainsString(
            'ORDER BY',
            $query->sql,
        );
        self::assertSame(
            ['smith', 'ou=people,dc=foo,dc=bar', '%,ou=people,dc=foo,dc=bar', 500],
            $query->params,
        );
    }

    public function test_streaming_root_query_omits_the_subtree_scope(): void
    {
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(
            '',
            true,
            $this->sidecarLeaf(),
            500,
            [],
        );

        self::assertStringContainsString(
            'IN (SELECT t.d FROM (',
            $query->sql,
        );
        self::assertStringNotContainsString(
            's.entry_lc_dn = ?',
            $query->sql,
        );
        self::assertSame(
            ['smith', 500],
            $query->params,
        );
    }

    public function test_mysql_produces_the_same_streaming_shape(): void
    {
        $query = (new PdoListQueryBuilder(new MysqlDialect()))->build(
            'ou=people,dc=foo,dc=bar',
            true,
            $this->sidecarLeaf(),
            500,
            [],
        );

        self::assertStringContainsString(
            'SELECT DISTINCT s.entry_lc_dn AS d',
            $query->sql,
        );
        self::assertStringContainsString(
            'IN (SELECT t.d FROM (',
            $query->sql,
        );
    }

    public function test_sort_keys_disable_the_streaming_fast_path(): void
    {
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(
            'ou=people,dc=foo,dc=bar',
            true,
            $this->sidecarLeaf(),
            500,
            [self::spec(SortKey::ascending('cn'))],
        );

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
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(
            'ou=people,dc=foo,dc=bar',
            true,
            $this->sidecarLeaf(),
            null,
            [],
        );

        self::assertStringNotContainsString(
            'SELECT t.d FROM (',
            $query->sql,
        );
    }

    public function test_absent_sidecar_condition_disables_the_streaming_fast_path(): void
    {
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(
            'ou=people,dc=foo,dc=bar',
            true,
            new SqlFilterResult('(a) AND (b)', ['x', 'y']),
            500,
            [],
        );

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
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(
            'ou=people,dc=foo,dc=bar',
            false,
            $this->sidecarLeaf(),
            500,
            [],
        );

        self::assertStringNotContainsString(
            'SELECT t.d FROM (',
            $query->sql,
        );
    }

    public function test_child_scope_uses_the_correlated_exists_form(): void
    {
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(
            'ou=people,dc=foo,dc=bar',
            false,
            $this->sidecarLeaf(),
            5001,
            [],
        );

        self::assertStringContainsString(
            'lc_parent_dn = ?',
            $query->sql,
        );
        self::assertStringContainsString(
            'EXISTS (',
            $query->sql,
        );
        self::assertStringContainsString(
            's.entry_lc_dn = lc_dn',
            $query->sql,
        );
        self::assertStringNotContainsString(
            'lc_dn IN (',
            $query->sql,
        );
    }

    public function test_child_scope_falls_back_to_the_in_form_without_a_correlated_form(): void
    {
        $query = (new PdoListQueryBuilder(new SqliteDialect()))->build(
            'ou=people,dc=foo,dc=bar',
            false,
            new SqlFilterResult(
                "lc_dn IN (SELECT s.entry_lc_dn FROM entry_attribute_values s WHERE s.attr_name_lower = 'cn')",
                [],
            ),
            5001,
            [],
        );

        self::assertStringContainsString(
            'lc_dn IN (',
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
            "lc_dn IN (SELECT s.entry_lc_dn FROM entry_attribute_values s WHERE s.attr_name_lower = 'cn' AND s.value_lower = ?)",
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
        $query = $builder->build(
            '',
            true,
            $filter,
            null,
            array_values(array_map(
                self::spec(...),
                $sortKeys,
            )),
        );

        return [$query->sql, $query->params];
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
