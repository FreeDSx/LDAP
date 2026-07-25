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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexReindexer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\TrigramSubstringIndex;
use PDO;
use PHPUnit\Framework\TestCase;

final class SubstringIndexReindexerTest extends TestCase
{
    private PDO $pdo;

    private PdoStorage $storage;

    private Dn $dn;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $index = new TrigramSubstringIndex();
        PdoStorage::initialize(
            $this->pdo,
            new SqliteDialect(),
            $index,
        );

        $this->storage = new PdoStorage(
            new SharedPdoConnectionProvider(
                $this->pdo,
                fn(): PDO => $this->pdo,
            ),
            (new SqliteDialect())->createFilterTranslator($index),
            new SqliteDialect(),
            $index,
        );

        $this->dn = new Dn('cn=Smith,dc=example,dc=com');
        $this->storage->store(new Entry(
            $this->dn,
            new Attribute('cn', 'Smith'),
            new Attribute('sn', 'Smith'),
            new Attribute('entryUUID', '11111111-2222-3333-4444-555555555555'),
            new Attribute('createTimestamp', '20260101000000Z'),
        ));
    }

    public function test_reindex_repopulates_the_substring_index(): void
    {
        // Simulate a directory that grew before substring indexing was enabled.
        $this->pdo->exec('DELETE FROM entry_attribute_trigrams');

        (new SubstringIndexReindexer($this->storage))->reindex();

        $count = $this->pdo->query('SELECT COUNT(*) FROM entry_attribute_trigrams');
        self::assertNotFalse($count);
        self::assertGreaterThan(
            0,
            (int) $count->fetchColumn(),
        );
    }

    public function test_reindex_preserves_entry_attributes(): void
    {
        $before = $this->storage->find($this->dn);
        self::assertNotNull($before);

        (new SubstringIndexReindexer($this->storage))->reindex();

        $after = $this->storage->find($this->dn);
        self::assertNotNull($after);
        self::assertEquals(
            $before->toArray(),
            $after->toArray(),
        );
    }
}
