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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract;

/**
 * Database-specific SQL for the sidecar table that indexes attribute values.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoSidecarDialectInterface
{
    /**
     * Delete every indexed value of an entry. Parameters: [owner_entry_id]
     */
    public function querySidecarDelete(): string;

    /**
     * Delete $count named values of an entry. Parameters: [owner_entry_id, then attr_name_lower, value_lower per pair]
     */
    public function querySidecarDeleteValues(int $count): string;

    /**
     * Insert $count values. Parameters: [owner_entry_id, attr_name_lower, value_lower, value_original per value]
     */
    public function querySidecarInsert(int $count): string;
}
