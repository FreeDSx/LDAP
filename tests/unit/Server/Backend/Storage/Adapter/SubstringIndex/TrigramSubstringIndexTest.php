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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\TrigramSubstringIndex;
use PHPUnit\Framework\TestCase;

final class TrigramSubstringIndexTest extends TestCase
{
    private const DN = 'cn=smith,dc=example,dc=com';

    private const ENTRY_ID = 42;

    /**
     * @var list<array{0: string, 1: array<array-key, mixed>}>
     */
    private array $executed = [];

    protected function setUp(): void
    {
        $this->executed = [];
    }

    public function test_maintain_deletes_then_inserts_the_trigram_rows(): void
    {
        (new TrigramSubstringIndex(['cn']))->maintain(
            self::ENTRY_ID,
            new Entry(
                new Dn(self::DN),
                new Attribute('cn', 'smith'),
            ),
            $this->recorder(),
        );

        self::assertStringContainsString(
            'DELETE FROM entry_attribute_trigrams',
            $this->executed[0][0],
        );
        self::assertSame(
            [self::ENTRY_ID],
            $this->executed[0][1],
        );
        self::assertStringContainsString(
            'INSERT INTO entry_attribute_trigrams',
            $this->executed[1][0],
        );
        self::assertSame(
            [
                self::ENTRY_ID, 'cn','smi',
                self::ENTRY_ID, 'cn','mit',
                self::ENTRY_ID, 'cn','ith',
            ],
            $this->executed[1][1],
        );
    }

    public function test_maintain_only_deletes_when_no_indexed_values_exist(): void
    {
        (new TrigramSubstringIndex(['cn']))->maintain(
            self::ENTRY_ID,
            new Entry(
                new Dn(self::DN),
                new Attribute('uid', 'smith'),
            ),
            $this->recorder(),
        );

        self::assertCount(
            1,
            $this->executed,
        );
        self::assertStringContainsString(
            'DELETE FROM entry_attribute_trigrams',
            $this->executed[0][0],
        );
    }

    public function test_maintain_indexes_only_configured_attributes(): void
    {
        (new TrigramSubstringIndex(['cn']))->maintain(
            self::ENTRY_ID,
            new Entry(
                new Dn(self::DN),
                new Attribute('cn', 'abc'),
                new Attribute('description', 'ignored'),
            ),
            $this->recorder(),
        );

        self::assertSame(
            [self::ENTRY_ID, 'cn', 'abc'],
            $this->executed[1][1],
        );
    }

    public function test_maintain_pools_distinct_trigrams_across_values(): void
    {
        (new TrigramSubstringIndex(['cn']))->maintain(
            self::ENTRY_ID,
            new Entry(
                new Dn(self::DN),
                new Attribute('cn', 'smith', 'smithy'),
            ),
            $this->recorder(),
        );

        self::assertSame(
            [
                self::ENTRY_ID, 'cn','smi',
                self::ENTRY_ID, 'cn','mit',
                self::ENTRY_ID, 'cn','ith',
                self::ENTRY_ID, 'cn','thy',
            ],
            $this->executed[1][1],
        );
    }

    public function test_build_substring_predicate_declines_an_unindexed_attribute(): void
    {
        self::assertNull(
            (new TrigramSubstringIndex(['cn']))->buildSubstringPredicate('mail', ['smith']),
        );
    }

    public function test_build_substring_predicate_declines_when_no_fragment_yields_a_trigram(): void
    {
        self::assertNull(
            (new TrigramSubstringIndex(['cn']))->buildSubstringPredicate('cn', ['ab']),
        );
    }

    public function test_build_substring_predicate_narrows_by_trigrams(): void
    {
        $result = (new TrigramSubstringIndex(['cn']))->buildSubstringPredicate('cn', ['smith']);

        self::assertNotNull($result);
        self::assertStringContainsString(
            'entry_attribute_trigrams',
            $result->sql,
        );
        self::assertStringContainsString(
            'HAVING COUNT(DISTINCT trigram) = 3',
            $result->sql,
        );
        self::assertFalse($result->isExact);
        self::assertSame(
            ['cn', 'smi', 'mit', 'ith', 'cn', "\x01"],
            $result->params,
            'The predicate also admits whatever the trigrams could not cover, which it re-checks in PHP.',
        );
    }

    public function test_maintain_marks_a_value_the_trigrams_cannot_cover(): void
    {
        (new TrigramSubstringIndex(['cn']))->maintain(
            self::ENTRY_ID,
            new Entry(
                new Dn(self::DN),
                new Attribute('cn', str_repeat('a', 300)),
            ),
            $this->recorder(),
        );

        self::assertSame(
            [self::ENTRY_ID, 'cn', "\x01"],
            $this->executed[1][1],
            'A value past the indexed window must be marked, not indexed by its first 255 characters alone.',
        );
    }

    public function test_maintain_marks_a_value_that_is_not_utf8(): void
    {
        (new TrigramSubstringIndex(['cn']))->maintain(
            self::ENTRY_ID,
            new Entry(
                new Dn(self::DN),
                new Attribute('cn', "\xFF\xD8\xFF\xE0abc"),
            ),
            $this->recorder(),
        );

        self::assertSame(
            [self::ENTRY_ID, 'cn', "\x01"],
            $this->executed[1][1],
        );
    }

    public function test_schema_statements_load_the_trigram_schema(): void
    {
        $statements = (new TrigramSubstringIndex())->schemaStatements(new SqliteDialect());

        self::assertStringContainsString(
            'entry_attribute_trigrams',
            implode("\n", $statements),
        );
    }

    /**
     * @return callable(string, list<string|int>): void
     */
    private function recorder(): callable
    {
        return function (string $sql, array $params): void {
            $this->executed[] = [$sql, $params];
        };
    }
}
