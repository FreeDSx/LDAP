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
use PDO;
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
    ) {}

    public function pdo(): PDO
    {
        return $this->provider->get();
    }

    /**
     * @param callable(): void $operation
     */
    public function atomic(callable $operation): void
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
            if ($transactionStarted) {
                $this->dialect->rollBack($pdo);
            } elseif ($savepointCreated) {
                $pdo->exec("ROLLBACK TO SAVEPOINT {$this->savepointName($depth)}");
            } elseif ($depth > 0) {
                // Savepoint creation itself failed; the outer transaction is now in an unknown state and must not be committed.
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
