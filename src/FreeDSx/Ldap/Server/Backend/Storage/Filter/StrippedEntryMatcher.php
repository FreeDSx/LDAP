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

use function array_diff_key;
use function array_values;
use function count;

/**
 * Tells whether withholding an attribute can change a filter's answer, and judges an entry again when it did.
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
     * Whether withholding a lowercased base type can change what the filter answers.
     */
    public function concerns(
        FilterInterface $filter,
        string $type,
    ): bool {
        $readSet = $this->readSets[$filter] ??= $this->readSetOf($filter);
        if ($readSet->types === null) {
            return true;
        }

        if (isset($readSet->concerns[$type])) {
            return $readSet->concerns[$type];
        }
        $concerns = $this->isRead(
            $readSet,
            $type,
        );
        if (count($readSet->concerns) < FilterReadSet::MAX_REMEMBERED) {
            $readSet->concerns[$type] = $concerns;
        }

        return $concerns;
    }

    /**
     * Whether an entry that matched the filter still does without the attributes access control withheld from it.
     *
     * @param array<array-key, true> $withheld The keys the entry holds its withheld attributes at.
     */
    public function stillMatches(
        Entry $entry,
        array $withheld,
        FilterInterface $filter,
    ): bool {
        return $this->evaluator->evaluate(
            Entry::raw(
                $entry->getDn(),
                array_values(array_diff_key(
                    $entry->getAttributes(),
                    $withheld,
                )),
            ),
            $filter,
        );
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
     * Whether the filter reads the type, directly or as a subtype of one it names.
     */
    private function isRead(
        FilterReadSet $readSet,
        string $type,
    ): bool {
        foreach ($readSet->types ?? [] as $readType) {
            if ($type === $readType || $this->schema->isTypeOrSubtypeOf($type, $readType)) {
                return true;
            }
        }

        return false;
    }
}
