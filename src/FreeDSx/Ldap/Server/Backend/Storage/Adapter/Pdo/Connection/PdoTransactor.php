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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Utility\ExponentialBackoff;
use PDO;
use PDOException;
use Throwable;

/**
 * Runs a callable inside a savepoint-aware transaction, shared by a storage adapter and its change journal.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PdoTransactor
{
    public function __construct(
        private PdoConnectionProviderInterface $provider,
        private PdoDialectInterface $dialect,
        private SleeperInterface $sleeper = new BlockingSleeper(),
        private int $maxRetries = 15,
        private ExponentialBackoff $backoff = new ExponentialBackoff(
            base: 0.001,
            max: 0.05,
        ),
    ) {}

    public function pdo(): PDO
    {
        return $this->provider->get();
    }

    /**
     * Runs within the caller's open transaction, starting one only when none is active.
     *
     * @param callable(): void $operation
     */
    public function joinAtomic(callable $operation): void
    {
        if ($this->provider->txState()->depth === 0) {
            $this->atomic($operation);

            return;
        }

        $operation();
    }

    /**
     * Runs the operation in a transaction, reissuing it when the database rejects it as a transient conflict.
     *
     * @param callable(): void $operation
     */
    public function atomic(callable $operation): void
    {
        $attempt = 0;

        while (true) {
            try {
                $this->runAtomic($operation);

                return;
            } catch (PDOException $e) {
                $attempt++;

                if (!$this->canRetry($e, $attempt)) {
                    throw $e;
                }

                $this->sleeper->sleep($this->backoff->delayFor($attempt));
            }
        }
    }

    /**
     * Only the outermost transaction can be reissued, since a savepoint cannot be replayed on its own.
     */
    private function canRetry(
        PDOException $exception,
        int $attempt,
    ): bool {
        return $attempt <= $this->maxRetries
            && $this->provider->txState()->depth === 0
            && $this->dialect->isRetryableConflict($exception);
    }

    /**
     * @param callable(): void $operation
     */
    private function runAtomic(callable $operation): void
    {
        $pdo = $this->provider->get();
        $txState = $this->provider->txState();

        $depth = $txState->depth++;
        $savepointCreated = false;
        $transactionStarted = false;

        try {
            if ($depth === 0) {
                $this->dialect->beginTransaction($pdo);
                $transactionStarted = true;
            } else {
                $pdo->exec("SAVEPOINT {$this->savepointName($depth)}");
                $savepointCreated = true;
            }

            $operation();

            if ($depth === 0 && $txState->broken) {
                $this->dialect->rollBack($pdo);
            } elseif ($depth === 0) {
                $this->dialect->commit($pdo);
            } else {
                $pdo->exec("RELEASE SAVEPOINT {$this->savepointName($depth)}");
            }
        } catch (Throwable $e) {
            try {
                if ($transactionStarted) {
                    $this->dialect->rollBack($pdo);
                } elseif ($savepointCreated) {
                    $pdo->exec("ROLLBACK TO SAVEPOINT {$this->savepointName($depth)}");
                } elseif ($depth > 0) {
                    // Savepoint creation itself failed; the outer transaction is now in an unknown state and must not be committed.
                    $txState->broken = true;
                }
            } catch (Throwable) {
                // Unwinding failed too
                // Keep the error that caused it and stop the outer transaction committing.
                $txState->broken = true;
            }

            throw $e;
        } finally {
            $txState->depth--;
            if ($txState->depth === 0) {
                $txState->broken = false;
            }
        }
    }

    private function savepointName(int $depth): string
    {
        return "sp_{$depth}";
    }
}
