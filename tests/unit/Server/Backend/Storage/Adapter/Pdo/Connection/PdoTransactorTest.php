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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
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
    private PdoDialectInterface&MockObject $dialect;

    private SharedPdoConnectionProvider $provider;

    private RecordingSleeper $sleeper;

    private PdoTransactor $subject;

    protected function setUp(): void
    {
        $this->dialect = $this->createMock(PdoDialectInterface::class);
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

    public function test_it_gives_up_once_the_retry_budget_is_spent(): void
    {
        $this->dialect->method('isRetryableConflict')
            ->willReturn(true);

        $attempts = 0;

        try {
            $this->subject->atomic(function () use (&$attempts): void {
                $attempts++;

                throw new PDOException('Deadlock found when trying to get lock');
            });
            self::fail('Expected the conflict to be rethrown.');
        } catch (PDOException) {
            // Expected once the budget is spent.
        }

        self::assertSame(
            4,
            $attempts,
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
            self::fail('Expected the conflict to be rethrown.');
        } catch (PDOException) {
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
}
