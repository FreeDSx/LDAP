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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect;

/**
 * An internal table whose rows a dialect locks, named by its value, with the columns each lock is keyed on.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum LockableTable: string
{
    case Entries = 'entries';

    case ReplicaPasswordState = 'ldap_replica_pwpolicy_state';

    public function keyColumn(): string
    {
        return match ($this) {
            self::Entries => 'lc_dn',
            self::ReplicaPasswordState => 'entry_uuid',
        };
    }

    /**
     * The unique index over the key column, which a lock by key must use rather than scan the table.
     */
    public function keyIndex(): string
    {
        return match ($this) {
            self::Entries => 'uq_lc_dn',
            self::ReplicaPasswordState => 'PRIMARY',
        };
    }
}
