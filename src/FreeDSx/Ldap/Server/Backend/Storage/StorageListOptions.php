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
     * @param list<string>|null $attributes Lowercase base attribute names to materialize, or null for all.
     * @param ?PageCursor $after Resume after this entry rather than starting from the beginning.
     * @param ?int $maxCandidates Stop after examining this many, so the caller can read the result to its end.
     */
    public function __construct(
        public Dn $baseDn,
        public bool $subtree,
        public FilterInterface $filter,
        public int $timeLimit = 0,
        public int $sizeLimit = 0,
        public array $sortKeys = [],
        public int $lookthroughLimit = 0,
        public ?array $attributes = null,
        public SubentryVisibility $subentries = SubentryVisibility::All,
        public ?PageCursor $after = null,
        public ?int $maxCandidates = null,
    ) {}

    /**
     * Every entry in scope, for internal callers that have no requested filter to apply.
     *
     * @param list<string>|null $attributes Lowercase base attribute names to materialize, or null for all.
     */
    public static function matchAll(
        Dn $baseDn,
        bool $subtree,
        int $timeLimit = 0,
        ?array $attributes = null,
    ): self {
        return new self(
            baseDn: $baseDn,
            subtree: $subtree,
            filter: new AndFilter(),
            timeLimit: $timeLimit,
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
            sizeLimit: 1,
            subentries: $subentries,
        );
    }
}
