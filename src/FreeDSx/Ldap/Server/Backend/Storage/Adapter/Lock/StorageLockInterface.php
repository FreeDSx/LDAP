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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock;

/**
 * Defines the strategy for atomically reading, mutating, and writing data.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface StorageLockInterface
{
    /**
     * Acquire exclusive access to the storage, pass the raw contents to the mutation callable, then persist the
     * returned string and release the lock.
     *
     * @param callable(string): string $mutation
     */
    public function withLock(callable $mutation): void;
}
