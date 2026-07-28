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
use Closure;

/**
 * DTO for EntryStorageInterface::list(), decoupled from LDAP protocol objects.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class StorageListOptions
{
    /**
     * @param SortKey[] $sortKeys
     * @param list<string>|null $attributes Lowercase base attribute names to materialize, or null for all.
     * @param (\Closure(string): (bool|null))|null $isIntegerOrderedResolver Resolves whether an attribute orders numerically.
     * @param (\Closure(string): (bool|null))|null $isCaseInsensitiveResolver Resolves whether an attribute matches without regard to case.
     */
    public function __construct(
        public readonly Dn $baseDn,
        public readonly bool $subtree,
        public readonly FilterInterface $filter,
        public readonly int $timeLimit = 0,
        public readonly int $sizeLimit = 0,
        public readonly array $sortKeys = [],
        public readonly int $lookthroughLimit = 0,
        public readonly ?array $attributes = null,
        public readonly ?Closure $isIntegerOrderedResolver = null,
        public readonly ?Closure $isCaseInsensitiveResolver = null,
    ) {}

    /**
     * Whether the attribute orders numerically. null when unresolved (no schema was supplied).
     */
    public function isIntegerOrdered(string $attribute): ?bool
    {
        return $this->isIntegerOrderedResolver !== null
            ? ($this->isIntegerOrderedResolver)($attribute)
            : null;
    }

    /**
     * Whether the attribute matches without regard to case. null when unresolved (no schema was supplied).
     */
    public function isCaseInsensitive(string $attribute): ?bool
    {
        return $this->isCaseInsensitiveResolver !== null
            ? ($this->isCaseInsensitiveResolver)($attribute)
            : null;
    }

    /**
     * Match-all options for internal callers (e.g. hasChildren) and tests that do not need a meaningful filter.
     */
    /**
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
}
