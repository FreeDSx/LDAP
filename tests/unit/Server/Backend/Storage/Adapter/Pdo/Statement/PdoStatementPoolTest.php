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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Pdo\RecordingPdo;

final class PdoStatementPoolTest extends TestCase
{
    private RecordingPdo $pdo;

    private PdoStatementPool $subject;

    protected function setUp(): void
    {
        $this->pdo = new RecordingPdo('sqlite::memory:');
        $this->pdo->setAttribute(
            PDO::ATTR_ERRMODE,
            PDO::ERRMODE_EXCEPTION,
        );
        $this->pdo->setAttribute(
            PDO::ATTR_DEFAULT_FETCH_MODE,
            PDO::FETCH_ASSOC,
        );
        $this->pdo->exec('CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)');
        $this->pdo->exec("INSERT INTO t (id, name) VALUES (1, 'a'), (2, 'b'), (3, 'c')");

        $this->subject = new PdoStatementPool(new SharedPdoConnectionProvider($this->pdo));
    }

    public function test_it_prepares_a_repeated_query_only_once(): void
    {
        $query = 'SELECT name FROM t WHERE id = ?';

        for ($i = 1; $i <= 3; $i++) {
            $this->subject->execute($query, [$i]);
        }

        self::assertCount(
            1,
            $this->pdo->preparedMatching('WHERE id = ?'),
        );
    }

    public function test_it_prepares_again_for_a_statement_still_held_open(): void
    {
        $query = 'SELECT name FROM t WHERE id = ?';

        $held = $this->subject->execute($query, [1]);
        $this->subject->execute($query, [2]);

        self::assertCount(
            2,
            $this->pdo->preparedMatching('WHERE id = ?'),
        );
        self::assertSame(
            ['name' => 'a'],
            $held->fetch(),
        );
    }

    public function test_it_evicts_the_least_recently_used_query_beyond_the_cap(): void
    {
        $pool = new PdoStatementPool(
            new SharedPdoConnectionProvider($this->pdo),
            maxQueries: 2,
        );

        $pool->execute('SELECT 1 FROM t');
        $pool->execute('SELECT 2 FROM t');
        // Re-running the first makes the second the least recently used.
        $pool->execute('SELECT 1 FROM t');
        $pool->execute('SELECT 3 FROM t');
        $pool->execute('SELECT 1 FROM t');
        $pool->execute('SELECT 2 FROM t');

        self::assertCount(
            1,
            $this->pdo->preparedMatching('SELECT 1 FROM t'),
        );
        self::assertCount(
            2,
            $this->pdo->preparedMatching('SELECT 2 FROM t'),
        );
    }

    public function test_reset_drops_every_pooled_statement(): void
    {
        $query = 'SELECT name FROM t WHERE id = ?';

        $this->subject->execute($query, [1]);
        $this->subject->reset();
        $this->subject->execute($query, [1]);

        self::assertCount(
            2,
            $this->pdo->preparedMatching('WHERE id = ?'),
        );
    }

    public function test_it_binds_an_int_parameter_as_an_integer(): void
    {
        $rows = [];
        $statement = $this->subject->execute(
            'SELECT name FROM t ORDER BY id LIMIT ?',
            [2],
        );

        while (($row = $statement->fetch()) !== false) {
            self::assertIsArray($row);
            $rows[] = $row['name'];
        }

        self::assertSame(
            ['a', 'b'],
            $rows,
        );
    }

    public function test_it_binds_a_null_parameter_as_sql_null(): void
    {
        $this->subject->execute(
            'INSERT INTO t (id, name) VALUES (?, ?)',
            [4, null],
        );

        self::assertSame(
            1,
            $this->subject
                ->execute('SELECT COUNT(*) FROM t WHERE name IS NULL')
                ->fetchIntColumn(),
        );
    }
}
