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

namespace FreeDSx\Ldap\Server\Backend\Storage;

/**
 * Optional interface for storage implementations that require transactional
 * read-modify-write semantics (e.g. file locking, database transactions).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface AtomicStorageInterface
{
    /**
     * Execute $operation as an atomic read-modify-write cycle.
     *
     * The EntryStorageInterface instance passed to $operation is a writable view
     * over the in-flight data for the duration of the call. Changes made to it
     * are committed when $operation returns.
     *
     * @param callable(EntryStorageInterface): void $operation
     */
    public function atomic(callable $operation): void;
}
