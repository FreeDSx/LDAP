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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use Closure;
use FreeDSx\Ldap\Exception\RuntimeException;
use PDO;

/**
 * Single shared PDO connection and transaction state; used by the PCNTL runner and unit tests with a pre-built PDO.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SharedPdoConnectionProvider implements PdoConnectionProviderInterface
{
    private ?PDO $pdo;

    private PdoTxState $txState;

    /**
     * @param Closure(): PDO|null $reconnectFactory Invoked by reset() to open a fresh PDO (required for fork-safe use)
     */
    public function __construct(
        ?PDO $pdo,
        private readonly ?Closure $reconnectFactory = null,
    ) {
        $this->pdo = $pdo;
        $this->txState = new PdoTxState();
    }

    public function get(): PDO
    {
        if ($this->pdo !== null) {
            return $this->pdo;
        }

        if ($this->reconnectFactory === null) {
            throw new RuntimeException(
                'No PDO connection is available and no reconnect factory was provided.'
            );
        }

        $this->pdo = ($this->reconnectFactory)();

        return $this->pdo;
    }

    public function txState(): PdoTxState
    {
        return $this->txState;
    }

    public function reset(): void
    {
        $this->pdo = null;
        $this->txState = new PdoTxState();
    }
}
