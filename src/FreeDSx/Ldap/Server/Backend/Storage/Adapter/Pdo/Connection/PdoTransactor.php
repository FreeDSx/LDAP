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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoTransactionDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageBusyException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
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
        private PdoTransactionDialectInterface $dialect,
        private SleeperInterface $sleeper = new BlockingSleeper(),
        private int $maxRetries = 15,
        private ExponentialBackoff $backoff = new ExponentialBackoff(
            base: 0.001,
            max: 0.05,
        ),
    ) {}

    /**
     * Runs within the caller's open transaction, starting one only when none is active.
     *
     * @template TResult
     *
     * @param callable(): TResult $operation
     *
     * @return TResult
     */
    public function joinAtomic(callable $operation): mixed
    {
        if ($this->provider->txState()->depth === 0) {
            return $this->atomic($operation);
        }

        return $operation();
    }

    /**
     * Runs the operation in a transaction, reissuing it when the database rejects it as a transient conflict.
     *
     * @template TResult
     *
     * @param callable(): TResult $operation
     *
     * @return TResult what the operation produced, once it has committed
     *
     * @throws StorageBusyException when the conflict outlasts the retry budget
     * @throws PDOException when the failure is not a transient conflict, or the transaction is nested
     */
    public function atomic(callable $operation): mixed
    {
        $attempt = 0;

        while (true) {
            try {
                return $this->runAtomic($operation);
            } catch (PDOException $e) {
                if (!$this->isReissuable($e)) {
                    throw $e;
                }

                $attempt++;

                if ($attempt > $this->maxRetries) {
                    throw new StorageBusyException(
                        'The transaction kept conflicting with concurrent writes.',
                        $e,
                    );
                }

                $this->sleeper->sleep($this->backoff->delayFor($attempt));
            }
        }
    }

    /**
     * Only the outermost transaction can be reissued, since a savepoint cannot be replayed on its own.
     */
    private function isReissuable(PDOException $exception): bool
    {
        return $this->provider->txState()->depth === 0
            && $this->dialect->isRetryableConflict($exception);
    }

    /**
     * @template TResult
     *
     * @param callable(): TResult $operation
     *
     * @return TResult
     */
    private function runAtomic(callable $operation): mixed
    {
        $pdo = $this->provider->get();
        $txState = $this->provider->txState();

        $depth = $txState->depth++;
        $began = false;
        $discarded = null;

        try {
            $this->begin(
                $pdo,
                $depth,
            );
            $began = true;

            $produced = $operation();

            $discarded = $this->finish(
                $pdo,
                $txState,
                $depth,
            );
        } catch (Throwable $e) {
            $this->unwind(
                $pdo,
                $txState,
                $depth,
                $began,
                $e,
            );

            throw $e;
        } finally {
            $txState->depth--;
            if ($txState->depth === 0) {
                $txState->clearBroken();
            }
        }

        // Thrown out here so the frame has already released its depth and the retry loop sees a settled state.
        if ($discarded !== null) {
            throw $discarded;
        }

        return $produced;
    }

    /**
     * Opens the outermost transaction, or a savepoint for anything nested inside it.
     */
    private function begin(
        PDO $pdo,
        int $depth,
    ): void {
        if ($depth === 0) {
            $this->dialect->beginTransaction($pdo);

            return;
        }

        $pdo->exec("SAVEPOINT {$this->savepointName($depth)}");
    }

    /**
     * Closes the frame, answering with the failure to rethrow when the transaction was discarded rather than committed.
     */
    private function finish(
        PDO $pdo,
        PdoTxState $txState,
        int $depth,
    ): ?Throwable {
        if ($depth > 0) {
            $pdo->exec("RELEASE SAVEPOINT {$this->savepointName($depth)}");

            return null;
        }

        if (!$txState->broken) {
            $this->dialect->commit($pdo);

            return null;
        }

        // Read before rolling back, since the state is cleared as this frame unwinds.
        $cause = $txState->cause ?? new StorageIoException('The transaction was rolled back.');
        $this->dialect->rollBack($pdo);

        return $cause;
    }

    /**
     * Undoes the frame, marking the transaction unusable when it cannot be unwound.
     */
    private function unwind(
        PDO $pdo,
        PdoTxState $txState,
        int $depth,
        bool $began,
        Throwable $cause,
    ): void {
        // Savepoint creation itself failed; the outer transaction is now in an unknown state and must not be committed.
        if (!$began && $depth > 0) {
            $txState->markBroken($cause);

            return;
        }

        if (!$began) {
            return;
        }

        try {
            if ($depth === 0) {
                $this->dialect->rollBack($pdo);
            } else {
                $pdo->exec("ROLLBACK TO SAVEPOINT {$this->savepointName($depth)}");
            }
        } catch (Throwable) {
            // Unwinding failed too, so keep the error that caused it and stop the outer transaction committing.
            $txState->markBroken($cause);
        }
    }

    private function savepointName(int $depth): string
    {
        return "sp_{$depth}";
    }
}
