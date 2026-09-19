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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Pdo\RecordingPdo;

final class PdoConnectionTest extends TestCase
{
    private RecordingPdo $first;

    private RecordingPdo $second;

    private PdoConnection $subject;

    protected function setUp(): void
    {
        $this->first = new RecordingPdo('sqlite::memory:');
        $this->second = new RecordingPdo('sqlite::memory:');
        $provider = new SharedPdoConnectionProvider(
            $this->first,
            fn(): RecordingPdo => $this->second,
        );

        $this->subject = new PdoConnection(
            $provider,
            new PdoStatementPool($provider),
            new PdoTransactor(
                $provider,
                new SqliteDialect(),
            ),
        );
    }

    public function test_reset_moves_the_next_query_onto_a_fresh_connection(): void
    {
        $this->subject->execute('SELECT 1');
        $this->subject->reset();
        $this->subject->execute('SELECT 1');

        self::assertCount(
            1,
            $this->first->preparedMatching('SELECT 1'),
        );
        self::assertCount(
            1,
            $this->second->preparedMatching('SELECT 1'),
        );
    }

    public function test_joining_an_open_transaction_opens_no_savepoint(): void
    {
        $this->subject->atomic(function (): void {
            $this->subject->joinAtomic(function (): void {
                $this->subject->execute('SELECT 1');
            });
        });

        self::assertSame(
            [],
            $this->first->executedMatching('SAVEPOINT'),
        );
    }

    public function test_it_hands_out_the_providers_current_connection(): void
    {
        self::assertSame(
            $this->first,
            $this->subject->pdo(),
        );
    }
}
