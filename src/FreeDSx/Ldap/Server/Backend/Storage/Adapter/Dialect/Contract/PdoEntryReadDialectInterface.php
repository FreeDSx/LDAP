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
 * Database-specific SQL for point reads of the entry table.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoEntryReadDialectInterface
{
    /**
     * A row when an entry exists at the DN. Parameters: [lc_dn]
     */
    public function queryExists(): string;

    /**
     * The entry at the DN. Parameters: [lc_dn]
     */
    public function queryFetchEntry(): string;

    /**
     * A row when any entry sits directly below the parent. Parameters: [lc_parent_dn]
     */
    public function queryHasChildren(): string;

    /**
     * The DN of every entry whose parent is not stored. No parameters.
     */
    public function queryNamingContexts(): string;
}
