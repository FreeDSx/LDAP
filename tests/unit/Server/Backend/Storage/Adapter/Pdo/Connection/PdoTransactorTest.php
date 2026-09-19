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

use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoTransactionDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageBusyException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Utility\ExponentialBackoff;
use PDO;
use PDOException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\Server\Clock\RecordingSleeper;

final class PdoTransactorTest extends TestCase
{
    private PdoTransactionDialectInterface&MockObject $dialect;

    private SharedPdoConnectionProvider $provider;

    private RecordingSleeper $sleeper;

    private PdoTransactor $subject;

    protected function setUp(): void
    {
        $this->dialect = $this->createMock(PdoTransactionDialectInterface::class);
        $this->provider = new SharedPdoConnectionProvider(new PDO('sqlite::memory:'));
        $this->sleeper = new RecordingSleeper();
        $this->subject = new PdoTransactor(
            $this->provider,
            $this->dialect,
            $this->sleeper,
            maxRetries: 3,
            backoff: new ExponentialBackoff(
                base: 0.001,
                max: 0.05,
                jitter: 0.0,
            ),
        );
    }

    public function test_it_reissues_the_transaction_until_the_conflict_clears(): void
    {
        $this->dialect->method('isRetryableConflict')
            ->willReturn(true);

        $attempts = 0;
        $this->subject->atomic(function () use (&$attempts): void {
            $attempts++;

            if ($attempts < 3) {
                throw new PDOException('Deadlock found when trying to get lock');
            }
        });

        self::assertSame(
            3,
            $attempts,
        );
        self::assertSame(
            [0.001, 0.002],
            $this->sleeper->durations,
        );
    }

    public function test_it_answers_busy_once_the_retry_budget_is_spent(): void
    {
        $this->dialect->method('isRetryableConflict')
            ->willReturn(true);

        $attempts = 0;
        $conflict = new PDOException('Deadlock found when trying to get lock');

        try {
            $this->subject->atomic(function () use (&$attempts, $conflict): void {
                $attempts++;

                throw $conflict;
            });
            self::fail('Expected the spent budget to answer busy.');
        } catch (StorageBusyException $e) {
            self::assertSame(
                ResultCode::BUSY,
                $e->getCode(),
            );
            self::assertSame(
                $conflict,
                $e->getPrevious(),
            );
        }

        self::assertSame(
            4,
            $attempts,
        );
    }

    public function test_a_nested_transaction_hands_the_raw_conflict_to_the_outermost_one(): void
    {
        $this->dialect->method('isRetryableConflict')
            ->willReturn(true);

        $caught = null;

        $this->subject->atomic(function () use (&$caught): void {
            try {
                $this->subject->atomic(static function (): void {
                    throw new PDOException('Deadlock found when trying to get lock');
                });
            } catch (PDOException $e) {
                $caught = $e;
            }
        });

        self::assertInstanceOf(
            PDOException::class,
            $caught,
        );
    }

    public function test_it_does_not_reissue_a_failure_the_dialect_does_not_own(): void
    {
        $this->dialect->method('isRetryableConflict')
            ->willReturn(false);

        $attempts = 0;

        $this->expectException(PDOException::class);

        try {
            $this->subject->atomic(function () use (&$attempts): void {
                $attempts++;

                throw new PDOException('Syntax error');
            });
        } finally {
            self::assertSame(
                1,
                $attempts,
            );
            self::assertSame(
                [],
                $this->sleeper->durations,
            );
        }
    }

    public function test_it_reissues_only_the_outermost_transaction(): void
    {
        $this->dialect->method('isRetryableConflict')
            ->willReturn(true);

        $outer = 0;
        $inner = 0;

        try {
            $this->subject->atomic(function () use (&$outer, &$inner): void {
                $outer++;

                $this->subject->atomic(function () use (&$inner): void {
                    $inner++;

                    throw new PDOException('Deadlock found when trying to get lock');
                });
            });
            self::fail('Expected the spent budget to answer busy.');
        } catch (StorageBusyException) {
            // Expected once the budget is spent.
        }

        self::assertSame(
            4,
            $outer,
        );
        self::assertSame(
            4,
            $inner,
        );
    }

    public function test_it_keeps_the_original_failure_when_unwinding_also_fails(): void
    {
        $this->dialect->method('isRetryableConflict')
            ->willReturn(false);
        $this->dialect->method('rollBack')
            ->willThrowException(new PDOException('SAVEPOINT sp_1 does not exist'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('the original failure');

        $this->subject->atomic(static function (): void {
            throw new RuntimeException('the original failure');
        });
    }

    public function test_it_does_not_reissue_a_non_database_failure(): void
    {
        $attempts = 0;

        $this->expectException(RuntimeException::class);

        try {
            $this->subject->atomic(function () use (&$attempts): void {
                $attempts++;

                throw new RuntimeException('application failure');
            });
        } finally {
            self::assertSame(
                1,
                $attempts,
            );
        }
    }

    public function test_it_surfaces_a_swallowed_nested_failure_from_the_outermost_transaction(): void
    {
        $this->dialect->method('isRetryableConflict')
            ->willReturn(false);

        $subject = $this->subjectOverUnwindableSavepoint();

        $this->expectException(PDOException::class);
        $this->expectExceptionMessage('Deadlock found when trying to get lock');

        $subject->atomic(static function () use ($subject): void {
            try {
                $subject->atomic(static function (): void {
                    throw new PDOException('Deadlock found when trying to get lock');
                });
            } catch (PDOException) {
                // Swallowed here, but the transaction it destroyed cannot report success.
            }
        });
    }

    public function test_it_reissues_a_swallowed_nested_conflict(): void
    {
        $this->dialect->method('isRetryableConflict')
            ->willReturn(true);

        $subject = $this->subjectOverUnwindableSavepoint();
        $attempts = 0;

        try {
            $subject->atomic(static function () use ($subject, &$attempts): void {
                $attempts++;

                try {
                    $subject->atomic(static function (): void {
                        throw new PDOException('Deadlock found when trying to get lock');
                    });
                } catch (PDOException) {
                }
            });
            self::fail('Expected the spent budget to answer busy.');
        } catch (StorageBusyException) {
            // Expected once the budget is spent.
        }

        self::assertSame(
            4,
            $attempts,
            'A conflict that destroyed the transaction must reach the retry loop, not be reported as success.',
        );
    }

    public function test_a_failed_begin_leaves_the_next_transaction_starting_fresh(): void
    {
        $begins = 0;
        $pdo = $this->pdoRunning(static function (string $sql) use (&$begins): void {
            if ($sql === 'BEGIN IMMEDIATE' && ++$begins === 1) {
                throw new RuntimeException('DB connection error');
            }
        });
        $subject = $this->subjectOver($pdo);

        try {
            $subject->atomic(static function (): void {});
            self::fail('Expected the failed begin to surface.');
        } catch (RuntimeException) {
            // Expected on the first begin.
        }
        // A depth left at one would open a savepoint here rather than a new transaction.
        $subject->atomic(static function (): void {});

        self::assertSame(
            2,
            $begins,
        );
    }

    public function test_a_failed_savepoint_surfaces_its_own_failure_and_unwinds_nothing_it_never_opened(): void
    {
        $executed = [];
        $pdo = $this->pdoRunning(static function (string $sql) use (&$executed): void {
            $executed[] = $sql;

            if ($sql === 'SAVEPOINT sp_1') {
                throw new RuntimeException('savepoint error');
            }
        });
        $subject = $this->subjectOver($pdo);

        try {
            $subject->atomic(static function () use ($subject): void {
                $subject->atomic(static function (): void {});
            });
            self::fail('Expected the savepoint failure to surface.');
        } catch (RuntimeException $e) {
            self::assertSame(
                'savepoint error',
                $e->getMessage(),
            );
        }

        self::assertNotContains(
            'ROLLBACK TO SAVEPOINT sp_1',
            $executed,
        );
    }

    public function test_a_failed_savepoint_rolls_the_outer_transaction_back_even_when_the_caller_swallows_it(): void
    {
        $executed = [];
        $pdo = $this->pdoRunning(static function (string $sql) use (&$executed): void {
            $executed[] = $sql;

            if ($sql === 'SAVEPOINT sp_1') {
                throw new RuntimeException('savepoint error');
            }
        });
        $subject = $this->subjectOver($pdo);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('savepoint error');

        try {
            $subject->atomic(static function () use ($subject): void {
                try {
                    $subject->atomic(static function (): void {});
                } catch (RuntimeException) {
                    // Swallowed here, but the transaction it broke cannot report success.
                }
            });
        } finally {
            self::assertNotContains(
                'COMMIT',
                $executed,
            );
            self::assertContains(
                'ROLLBACK',
                $executed,
            );
        }
    }

    public function test_a_broken_transaction_does_not_leak_into_the_next_one(): void
    {
        $savepoints = 0;
        $commits = 0;
        $pdo = $this->pdoRunning(static function (string $sql) use (&$savepoints, &$commits): void {
            if ($sql === 'SAVEPOINT sp_1' && ++$savepoints === 1) {
                throw new RuntimeException('savepoint error');
            }
            if ($sql === 'COMMIT') {
                $commits++;
            }
        });
        $subject = $this->subjectOver($pdo);

        try {
            $subject->atomic(static function () use ($subject): void {
                try {
                    $subject->atomic(static function (): void {});
                } catch (RuntimeException) {
                    // Swallowed, which breaks the outer transaction.
                }
            });
        } catch (RuntimeException) {
            // Expected, since the broken transaction rolls back.
        }
        $subject->atomic(static function (): void {});

        self::assertSame(
            1,
            $commits,
        );
    }

    /**
     * A connection that hands every statement it executes to the given callback, which throws to fail one.
     *
     * @param callable(string): void $onExec
     */
    private function pdoRunning(callable $onExec): PDO&MockObject
    {
        $pdo = $this->createMock(PDO::class);
        $pdo->method('exec')
            ->willReturnCallback(static function (string $sql) use ($onExec): int {
                $onExec($sql);

                return 0;
            });

        return $pdo;
    }

    /**
     * A transactor over the given connection that issues SQLite's real transaction statements.
     */
    private function subjectOver(PDO $pdo): PdoTransactor
    {
        return new PdoTransactor(
            new SharedPdoConnectionProvider($pdo),
            new SqliteDialect(),
            $this->sleeper,
        );
    }

    /**
     * A transactor whose savepoint cannot be rolled back, as when a deadlock has already discarded the transaction.
     */
    private function subjectOverUnwindableSavepoint(): PdoTransactor
    {
        /** @var PDO&MockObject $pdo */
        $pdo = $this->createMock(PDO::class);
        $pdo->method('exec')
            ->willReturnCallback(static function (string $sql): int {
                if (str_starts_with($sql, 'ROLLBACK TO SAVEPOINT')) {
                    throw new PDOException('Deadlock found when trying to get lock');
                }

                return 0;
            });

        return new PdoTransactor(
            new SharedPdoConnectionProvider($pdo),
            $this->dialect,
            $this->sleeper,
            maxRetries: 3,
            backoff: new ExponentialBackoff(
                base: 0.001,
                max: 0.05,
                jitter: 0.0,
            ),
        );
    }
}
