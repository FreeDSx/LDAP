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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SortedQuery;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SortKeySpec;

/**
 * Database-specific SQL for listing entries by scope.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoEntryListDialectInterface
{
    /**
     * Every entry, optionally flagging which have children. No parameters.
     */
    public function queryFetchAll(bool $withChildFlag = false): string;

    /**
     * The entries directly below a parent, optionally flagging which have children. Parameters: [lc_parent_dn]
     */
    public function queryFetchChildren(bool $withChildFlag = false): string;

    /**
     * The base entry and its descendants, optionally flagging which have children. Parameters: [lc_dn]
     */
    public function querySubtree(bool $withChildFlag = false): string;

    /**
     * A parameterless condition restricting $dnColumn to entries that lack, or carry, the subentry object class.
     */
    public function querySubentryCondition(
        string $dnColumn,
        bool $exclude,
    ): string;

    /**
     * The base query ordered by the sort keys, with missing values ordered per RFC 2891 §2.2.
     *
     * @param list<string|int> $baseParams
     * @param list<SortKeySpec> $sortKeys
     */
    public function sortedQuery(
        string $baseSql,
        array $baseParams,
        array $sortKeys,
    ): SortedQuery;
}
