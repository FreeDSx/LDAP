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
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;

/**
 * DTO for EntryStorageInterface::list(), decoupled from LDAP protocol objects.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class StorageListOptions
{
    /**
     * @param SortKey[] $sortKeys
     * @param ?float $deadline When the read must stop, established by the caller that knows the operation it serves.
     * @param int $maxEntries A hard row cap for internal callers that want a bounded read; never the client's size
     *                        limit, which access control can shrink after the read and so cannot bound it here.
     * @param list<string>|null $attributes Lowercase base attribute names to materialize, or null for all.
     * @param ?PageSlice $slice Where to resume and how many candidates to examine, for a caller reading a page.
     */
    public function __construct(
        public Dn $baseDn,
        public bool $subtree,
        public FilterInterface $filter,
        public ?float $deadline = null,
        public int $maxEntries = 0,
        public array $sortKeys = [],
        public int $lookthroughLimit = 0,
        public ?array $attributes = null,
        public SubentryVisibility $subentries = SubentryVisibility::All,
        private ?PageSlice $slice = null,
        public bool $withHasSubordinates = false,
    ) {}

    /**
     * Candidates this read may examine, or null when it is not bounded to a page.
     */
    public function limit(): ?int
    {
        return $this->slice?->limit;
    }

    /**
     * Where to resume, or null to start from the beginning.
     */
    public function resumeAfter(): ?PageCursor
    {
        return $this->slice?->after;
    }

    /**
     * Every entry in scope, for internal callers that have no requested filter to apply.
     *
     * @param list<string>|null $attributes Lowercase base attribute names to materialize, or null for all.
     */
    public static function matchAll(
        Dn $baseDn,
        bool $subtree,
        ?float $deadline = null,
        ?array $attributes = null,
    ): self {
        return new self(
            baseDn: $baseDn,
            subtree: $subtree,
            filter: new AndFilter(),
            deadline: $deadline,
            attributes: $attributes,
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
            baseDn: $baseDn,
            subtree: false,
            filter: new AndFilter(),
            maxEntries: 1,
            subentries: $subentries,
        );
    }
}
