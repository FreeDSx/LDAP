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
use FreeDSx\Ldap\Search\Filter\AttributeValueAssertionInterface;
use FreeDSx\Ldap\Search\Filter\FilterAttributeInterface;
use FreeDSx\Ldap\Search\Filter\FilterContainerInterface;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\LinkedValueLookupInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;

/**
 * Puts the linked values a filter asks about onto the entry it is judged against.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LinkedLeafWitness
{
    public function __construct(
        private LinkedValueLookupInterface $links,
        private LinkedAttributes $linked,
    ) {}

    /**
     * The entry as the filter needs to see it, also holding whichever of the asserted values it links.
     */
    public function witness(
        Entry $entry,
        FilterInterface $filter,
    ): Entry {
        if ($this->linked->isEmpty()) {
            return $entry;
        }
        $asserted = [];
        $this->collect($filter, $asserted);

        if ($asserted === []) {
            return $entry;
        }

        return $this->answering($entry, $asserted);
    }

    /**
     * A copy carrying the asserted linked values as well, since a bounded read may have stopped short of them.
     *
     * @param array<string, list<string>> $asserted
     */
    private function answering(
        Entry $entry,
        array $asserted,
    ): Entry {
        $copy = $entry->makeCopy();

        foreach ($asserted as $name => $values) {
            $held = $this->heldOf($entry, $name, $values);

            if ($held !== []) {
                $copy->add($name, ...$held);
            }
        }

        return $copy;
    }

    /**
     * @param list<string> $values
     *
     * @return list<string>
     */
    private function heldOf(
        Entry $entry,
        string $name,
        array $values,
    ): array {
        $held = $values === []
            ? []
            : $this->links->heldLinkValues($entry->getDn(), $name, $values);

        if ($held !== [] || $entry->get($name, true) !== null) {
            return $held;
        }
        // The entry shows none of the attribute, which leaves whether it holds any at all still open.
        $any = $this->links->anyLinkValue($entry->getDn(), $name);

        return $any === null
            ? []
            : [$any];
    }

    /**
     * Every linked attribute the filter names, against the values it asserts of each.
     *
     * @param array<string, list<string>> $asserted
     */
    private function collect(
        FilterInterface $filter,
        array &$asserted,
    ): void {
        if ($filter instanceof NotFilter) {
            $this->collect($filter->get(), $asserted);

            return;
        }

        if ($filter instanceof FilterContainerInterface) {
            foreach ($filter->get() as $child) {
                $this->collect($child, $asserted);
            }

            return;
        }

        if (!$filter instanceof FilterAttributeInterface) {
            return;
        }
        $name = $filter->getAttribute();

        // An extensible match may name no attribute at all, which no linked value answers.
        if ($name === null) {
            return;
        }
        // Held apart from the entry, so a bounded read may have stopped short of the values asserted.
        if (!$this->linked->heldApart(new Attribute($name))) {
            return;
        }
        $normalized = Attribute::normalizeName($name);
        $asserted[$normalized] ??= [];

        if ($filter instanceof AttributeValueAssertionInterface) {
            $asserted[$normalized][] = $filter->getValue();
        }
    }
}
