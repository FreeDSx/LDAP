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

namespace Tests\Integration\FreeDSx\Ldap\Server\Backend\Storage\Journal;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\PdoChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use PDO;
use Tests\Support\FreeDSx\Ldap\Journal\JournalConcurrencyTestCase;

final class PdoChangeJournalConcurrencyTest extends JournalConcurrencyTestCase
{
    private string $dbPath = '';

    protected function tearDown(): void
    {
        // setUp() may skip (no pcntl) before $dbPath is assigned, so there is nothing to clean.
        if ($this->dbPath === '') {
            return;
        }

        foreach ([$this->dbPath, $this->dbPath . '-wal', $this->dbPath . '-shm'] as $path) {
            if (is_file($path)) {
                @unlink($path);
            }
        }
    }

    protected function prepareJournalStore(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'journal-concurrency-');
        self::assertIsString($path);
        $this->dbPath = $path;

        // Create the schema once, up front, then drop the connection before forking so no handle is inherited.
        $pdo = $this->connect();
        PdoStorage::initialize($pdo, new SqliteDialect());
        unset($pdo);
    }

    protected function makeJournal(): ChangeJournalInterface
    {
        $dialect = new SqliteDialect();
        $provider = new SharedPdoConnectionProvider($this->connect());

        return new PdoChangeJournal(
            new PdoTransactor(
                $provider,
                $dialect,
            ),
            $dialect,
            new PdoStatementPool($provider),
            new ReplicaId('node'),
        );
    }

    private function connect(): PDO
    {
        $pdo = new PDO('sqlite:' . $this->dbPath);
        $pdo->setAttribute(
            PDO::ATTR_ERRMODE,
            PDO::ERRMODE_EXCEPTION,
        );
        // WAL + a generous busy timeout: concurrent BEGIN IMMEDIATE writers wait for the lock instead of erroring.
        $pdo->exec('PRAGMA journal_mode=WAL');
        $pdo->exec('PRAGMA busy_timeout=10000');

        return $pdo;
    }
}
