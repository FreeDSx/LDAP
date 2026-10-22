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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Error;

/**
 * A driver failure, read as the database that raised it means it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoErrorInterface
{
    /**
     * Whether the database guarantees the failed transaction applied nothing, making it safe to reissue.
     */
    public function isRetryableConflict(): bool;

    /**
     * Whether the unique key on lc_dn refused a second entry at one DN.
     */
    public function isDuplicateDn(): bool;

    /**
     * Whether the unique key on entry_uuid refused a second entry with one entryUUID.
     */
    public function isDuplicateEntryUuid(): bool;

    /**
     * Whether a value exceeded its column's declared length.
     */
    public function isValueTooLong(): bool;

    /**
     * Whether the connection itself is gone and has to be replaced before it is used again.
     */
    public function isConnectionLost(): bool;
}
