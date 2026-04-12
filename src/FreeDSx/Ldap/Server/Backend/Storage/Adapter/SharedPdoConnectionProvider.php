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

use PDO;

/**
 * Returns a single shared PDO connection and transaction state.
 *
 * Used by the PCNTL runner and by unit tests that inject a pre-built PDO.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SharedPdoConnectionProvider implements PdoConnectionProviderInterface
{
    private readonly PdoTxState $txState;

    public function __construct(private readonly PDO $pdo)
    {
        $this->txState = new PdoTxState();
    }

    public function get(): PDO
    {
        return $this->pdo;
    }

    public function txState(): PdoTxState
    {
        return $this->txState;
    }
}
