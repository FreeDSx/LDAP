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

use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageSlice;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\Search\Options\ListScope;
use FreeDSx\Ldap\Server\Backend\Storage\Search\Options\ReadBounds;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;

/**
 * What ListEntryInterface::list() reads: its scope, filter, per-entry shape, order and bounds.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class StorageListOptions
{
    /**
     * @param SortKey[] $sortKeys
     */
    public function __construct(
        public ListScope $scope,
        public FilterInterface $filter,
        public EntryProjection $projection = new EntryProjection(),
        public array $sortKeys = [],
        public ReadBounds $bounds = new ReadBounds(),
    ) {}

    /**
     * Every entry in scope, for internal callers that have no requested filter to apply.
     */
    public static function matchAll(
        Dn $baseDn,
        bool $subtree,
        ?float $deadline = null,
        EntryProjection $projection = new EntryProjection(),
    ): self {
        return new self(
            scope: new ListScope(
                baseDn: $baseDn,
                subtree: $subtree,
            ),
            filter: new AndFilter(),
            projection: $projection,
            bounds: new ReadBounds(deadline: $deadline),
        );
    }

    /**
     * One page of the entries directly below the parent, each flagged with whether it has children of its own.
     */
    public static function forChildPage(
        Dn $parent,
        int $limit,
        ?PageCursor $after = null,
    ): self {
        return new self(
            scope: new ListScope(
                baseDn: $parent,
                subtree: false,
                subentries: SubentryVisibility::All,
            ),
            filter: new AndFilter(),
            projection: new EntryProjection(
                attributes: [],
                linkCap: 0,
                withHasSubordinates: true,
            ),
            bounds: new ReadBounds(slice: new PageSlice(
                $limit,
                $after,
            )),
        );
    }

    /**
     * One entry directly below the base, for callers asking only whether anything is there.
     */
    public static function firstChild(
        Dn $baseDn,
        SubentryVisibility $subentries = SubentryVisibility::All,
    ): self {
        return new self(
            scope: new ListScope(
                baseDn: $baseDn,
                subtree: false,
                subentries: $subentries,
            ),
            filter: new AndFilter(),
            bounds: new ReadBounds(slice: new PageSlice(1)),
        );
    }
}
