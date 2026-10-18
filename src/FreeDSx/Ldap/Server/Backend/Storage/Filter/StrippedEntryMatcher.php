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

namespace FreeDSx\Ldap\Server\Backend\Storage\Filter;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Search\Filter\FilterAttributes;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedAttributeTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use WeakMap;

use function array_values;
use function count;
use function strtolower;

/**
 * Judges an entry access control stripped against the filter again whenever an attribute it lost is one the filter reads.
 *
 * @internal
 */
class StrippedEntryMatcher
{
    use DerivedAttributeTrait;

    /**
     * @var WeakMap<FilterInterface, FilterReadSet>
     */
    private WeakMap $readSets;

    public function __construct(
        private readonly FilterEvaluatorInterface $evaluator,
        private readonly Schema $schema,
        private readonly LinkedAttributes $linked,
    ) {
        $this->readSets = new WeakMap();
    }

    /**
     * Whether the stripped entry still matches a filter the entry it was stripped from already matched.
     */
    public function stillMatches(
        Entry $entry,
        Entry $stripped,
        FilterInterface $filter,
    ): bool {
        if ($stripped === $entry) {
            return true;
        }

        if (!$this->lostAnyRead($entry, $stripped, $filter)) {
            return true;
        }

        return $this->evaluator->evaluate(
            $stripped,
            $filter,
        );
    }

    private function lostAnyRead(
        Entry $entry,
        Entry $stripped,
        FilterInterface $filter,
    ): bool {
        $readSet = $this->readSets[$filter] ??= $this->readSetOf($filter);
        $removed = self::removed(
            $entry,
            $stripped,
        );

        if ($readSet->types === null || $removed === null) {
            return true;
        }

        foreach ($removed as $attribute) {
            if ($this->concerns($readSet, strtolower($attribute->getName()))) {
                return true;
            }
        }

        return false;
    }

    private function readSetOf(FilterInterface $filter): FilterReadSet
    {
        $types = FilterAttributes::referenced($filter);

        // A filter naming a derived or linked type is always judged again.
        foreach ($types ?? [] as $type) {
            if (self::describesAnyDerivedAttribute($type) || $this->linked->heldApart(new Attribute($type))) {
                return new FilterReadSet(null);
            }
        }

        return new FilterReadSet($types);
    }

    /**
     * Whether a removed type is one the filter reads, directly or as a subtype of one it names.
     */
    private function concerns(
        FilterReadSet $readSet,
        string $removedType,
    ): bool {
        if (isset($readSet->concerns[$removedType])) {
            return $readSet->concerns[$removedType];
        }
        $concerns = false;

        foreach ($readSet->types ?? [] as $type) {
            if ($removedType === $type || $this->schema->isTypeOrSubtypeOf($removedType, $type)) {
                $concerns = true;

                break;
            }
        }

        if (count($readSet->concerns) < FilterReadSet::MAX_REMEMBERED) {
            $readSet->concerns[$removedType] = $concerns;
        }

        return $concerns;
    }

    /**
     * The attributes stripping removed, or null when the stripped entry is not an ordered subset of the original.
     *
     * @return list<Attribute>|null
     */
    private static function removed(
        Entry $entry,
        Entry $stripped,
    ): ?array {
        $kept = array_values($stripped->getAttributes());
        $keptCount = count($kept);
        $removed = [];
        $next = 0;

        foreach ($entry->getAttributes() as $attribute) {
            if ($next < $keptCount && $kept[$next] === $attribute) {
                $next++;

                continue;
            }
            $removed[] = $attribute;
        }

        return $next === $keptCount
            ? $removed
            : null;
    }
}
