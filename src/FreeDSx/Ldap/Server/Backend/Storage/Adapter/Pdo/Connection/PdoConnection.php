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

use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PooledStatement;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageBusyException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use PDO;

/**
 * One connection provider together with the statement pool and transactor drawn from it.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class PdoConnection implements TransactionalWriteInterface, ResettableInterface
{
    /**
     * @param PdoStatementPool $statements Must draw from $provider.
     * @param PdoTransactor $transactor Must draw from $provider.
     */
    public function __construct(
        private PdoConnectionProviderInterface $provider,
        private PdoStatementPool $statements,
        private PdoTransactor $transactor,
    ) {}

    /**
     * @param list<string|int|null> $params
     *
     * @throws StorageIoException when the statement cannot be prepared
     */
    public function execute(
        string $query,
        array $params = [],
    ): PooledStatement {
        return $this->statements->execute(
            $query,
            $params,
        );
    }

    /**
     * @param callable(): void $operation
     *
     * @throws StorageBusyException when a transient conflict outlasts the retry budget
     */
    public function atomic(callable $operation): void
    {
        $this->transactor->atomic($operation);
    }

    /**
     * Runs within the caller's open transaction, starting one only when none is active.
     *
     * @param callable(): void $operation
     */
    public function joinAtomic(callable $operation): void
    {
        $this->transactor->joinAtomic($operation);
    }

    public function pdo(): PDO
    {
        return $this->provider->get();
    }

    /**
     * Drops the connection and every statement prepared on it, for when the process no longer owns them.
     */
    public function reset(): void
    {
        $this->provider->reset();
        $this->statements->reset();
    }
}
