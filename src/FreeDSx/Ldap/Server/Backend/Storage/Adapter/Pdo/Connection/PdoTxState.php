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

use Throwable;

/**
 * Mutable transaction-depth counter bound to a single PDO connection.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PdoTxState
{
    public int $depth = 0;

    /**
     * Set when a nested savepoint fails before it is established.
     */
    public bool $broken = false;

    /**
     * The failure that broke the transaction.
     */
    public ?Throwable $cause = null;

    public function markBroken(Throwable $cause): void
    {
        $this->broken = true;
        $this->cause ??= $cause;
    }

    public function clearBroken(): void
    {
        $this->broken = false;
        $this->cause = null;
    }
}
