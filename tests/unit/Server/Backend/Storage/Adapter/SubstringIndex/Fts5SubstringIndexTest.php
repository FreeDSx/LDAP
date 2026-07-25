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
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\EntryIndexWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\Fts5SubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use PDO;
use PHPUnit\Framework\TestCase;

final class Fts5SubstringIndexTest extends TestCase
{
    public function test_build_substring_predicate_declines_an_unindexed_attribute(): void
    {
        self::assertNull(
            (new Fts5SubstringIndex(['cn']))->buildSubstringPredicate('mail', ['smith']),
        );
    }

    public function test_build_substring_predicate_declines_fragments_shorter_than_three_chars(): void
    {
        self::assertNull(
            (new Fts5SubstringIndex(['cn']))->buildSubstringPredicate('cn', ['ab']),
        );
    }

    public function test_build_substring_predicate_emits_an_fts_match(): void
    {
        $result = (new Fts5SubstringIndex(['cn']))->buildSubstringPredicate('cn', ['smith', 'jones']);

        self::assertNotNull($result);
        self::assertStringContainsString(
            'entry_attribute_fts MATCH ?',
            $result->sql,
        );
        self::assertFalse($result->isExact);
        self::assertSame(
            ['cn', '"smith" AND "jones"'],
            $result->params,
        );
    }

    public function test_schema_statements_scope_the_triggers_to_the_indexed_attributes(): void
    {
        $statements = implode(
            "\n",
            (new Fts5SubstringIndex(['cn', 'sn']))->schemaStatements(new SqliteDialect()),
        );

        self::assertStringContainsString(
            "USING fts5(",
            $statements,
        );
        self::assertStringContainsString(
            "attr_name_lower IN ('cn', 'sn')",
            $statements,
        );
    }

    public function test_infix_search_matches_substrings_precisely(): void
    {
        if (!Fts5SubstringIndex::isSupported()) {
            self::markTestSkipped('This SQLite build lacks the FTS5 trigram tokenizer.');
        }

        $pdo = new PDO('sqlite::memory:');
        $index = new Fts5SubstringIndex();
        PdoStorage::initialize(
            $pdo,
            new SqliteDialect(),
            $index,
        );

        $provider = new SharedPdoConnectionProvider(
            $pdo,
            fn(): PDO => $pdo,
        );
        $statements = new PdoStatementPool($provider);
        $storage = new PdoStorage(
            $provider,
            (new SqliteDialect())->createFilterTranslator($index),
            new SqliteDialect(),
            $statements,
            new EntryIndexWriter(
                new SqliteDialect(),
                $statements,
                $index,
            ),
        );

        $storage->store(new Entry(
            new Dn('cn=blacksmith,dc=example,dc=com'),
            new Attribute('cn', 'blacksmith'),
        ));
        $storage->store(new Entry(
            new Dn('cn=scatter,dc=example,dc=com'),
            new Attribute('cn', 'smi mit ith'),
        ));

        $stream = $storage->list(new StorageListOptions(
            baseDn: new Dn('dc=example,dc=com'),
            subtree: true,
            filter: Filters::contains('cn', 'smith'),
        ));

        $dns = [];
        foreach ($stream->entries as $entry) {
            $dns[] = $entry->getDn()->toString();
        }

        self::assertSame(
            ['cn=blacksmith,dc=example,dc=com'],
            $dns,
        );
    }
}
