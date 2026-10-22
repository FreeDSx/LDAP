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

use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\ConnectionLoss;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Error\PdoErrorFactory;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Config\Storage\PdoDriver;
use PDO;
use PDOException;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Pdo\DriverFailure;
use Tests\Support\FreeDSx\Ldap\Pdo\DroppablePdo;
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

        $this->subject = $this->poolOver(new SharedPdoConnectionProvider($this->pdo));
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
        $provider = new SharedPdoConnectionProvider($this->pdo);
        $pool = new PdoStatementPool(
            $provider,
            $this->connectionLossOver($provider),
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

    public function test_it_drops_pooled_statements_when_the_provider_releases_the_connection(): void
    {
        $query = 'SELECT name FROM t WHERE id = ?';
        $provider = new SharedPdoConnectionProvider(
            $this->pdo,
            fn(): PDO => $this->pdo,
        );
        $pool = $this->poolOver($provider);

        $pool->execute($query, [1]);
        $provider->reset();
        $pool->execute($query, [2]);

        self::assertCount(
            2,
            $this->pdo->preparedMatching('WHERE id = ?'),
            'A statement cached against a released connection would keep that connection alive.',
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

    public function test_a_string_column_answers_null_once_the_rows_run_out(): void
    {
        $statement = $this->subject->execute(
            'SELECT name FROM t WHERE id <= ? ORDER BY id',
            [2],
        );

        self::assertSame(
            ['a', 'b', null],
            [
                $statement->fetchStringColumn(),
                $statement->fetchStringColumn(),
                $statement->fetchStringColumn(),
            ],
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

    public function test_a_lost_connection_is_answered_as_unavailable_and_the_next_query_reconnects(): void
    {
        $dropped = new DroppablePdo('sqlite::memory:');
        $dropped->drop(DriverFailure::of(
            10,
            'disk I/O error',
        ));
        $pool = $this->poolOver(new SharedPdoConnectionProvider(
            $dropped,
            fn(): PDO => $this->pdo,
        ));

        try {
            $pool->execute(
                'SELECT name FROM t WHERE id = ?',
                [1],
            );
            self::fail('Expected the lost connection to surface.');
        } catch (StorageIoException $e) {
            self::assertSame(
                ResultCode::UNAVAILABLE,
                $e->getCode(),
            );
        }

        self::assertSame(
            ['name' => 'a'],
            $pool->execute(
                'SELECT name FROM t WHERE id = ?',
                [1],
            )->fetch(),
        );
    }

    public function test_a_failure_that_keeps_the_connection_is_rethrown_as_it_is(): void
    {
        $this->expectException(PDOException::class);

        $this->subject->execute('SELECT missing FROM t');
    }

    private function poolOver(SharedPdoConnectionProvider $provider): PdoStatementPool
    {
        return new PdoStatementPool(
            $provider,
            $this->connectionLossOver($provider),
        );
    }

    private function connectionLossOver(SharedPdoConnectionProvider $provider): ConnectionLoss
    {
        return new ConnectionLoss(
            $provider,
            new PdoErrorFactory(PdoDriver::Sqlite),
        );
    }
}
