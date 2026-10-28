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
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use WeakMap;

use function count;

/**
 * Tells whether withholding an attribute can change a filter's answer, and judges an entry again when it did.
 *
 * @internal
 */
class StrippedEntryMatcher
{
    /**
     * @var WeakMap<FilterInterface, FilterReadSet>
     */
    private WeakMap $readSets;

    public function __construct(
        private readonly FilterEvaluatorInterface $evaluator,
        private readonly Schema $schema,
        private readonly LinkedAttributes $linked,
        private readonly LinkedLeafWitness $linkedLeaves,
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
        $readSet = $this->readSetOf($filter);
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
     * The lowercased linked types the filter names, which an entry may match on without carrying their values.
     *
     * @return list<string>
     */
    public function linkedTypes(FilterInterface $filter): array
    {
        return $this->readSetOf($filter)->linked;
    }

    /**
     * Whether an entry that matched the filter still does without the types access control withheld from it.
     *
     * @param array<string, true> $withheld Lowercased base types the filter reads that may not be read on the entry.
     */
    public function stillMatches(
        Entry $entry,
        array $withheld,
        FilterInterface $filter,
    ): bool {
        $readable = [];

        foreach ($entry->getAttributes() as $attribute) {
            if (!isset($withheld[Attribute::normalizeName($attribute->getName())])) {
                $readable[] = $attribute;
            }
        }

        // Linked values the entry does not carry still count, unless their type is withheld too.
        return $this->evaluator->evaluate(
            $this->linkedLeaves->witness(
                Entry::raw(
                    $entry->getDn(),
                    $readable,
                ),
                $filter,
                $withheld,
            ),
            $filter,
        );
    }

    private function readSetOf(FilterInterface $filter): FilterReadSet
    {
        return $this->readSets[$filter] ??= $this->newReadSet($filter);
    }

    private function newReadSet(FilterInterface $filter): FilterReadSet
    {
        $types = FilterAttributes::referenced($filter);
        $linked = [];

        foreach ($types ?? [] as $type) {
            if ($this->linked->heldApart(new Attribute($type))) {
                $linked[] = $type;
            }
        }

        return new FilterReadSet(
            $types,
            $linked,
        );
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
