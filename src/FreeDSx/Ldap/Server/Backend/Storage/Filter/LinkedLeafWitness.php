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
use FreeDSx\Ldap\Search\Filter\AttributeValueAssertionInterface;
use FreeDSx\Ldap\Search\Filter\FilterAttributeInterface;
use FreeDSx\Ldap\Search\Filter\FilterContainerInterface;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\LinkedValueLookupInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use WeakMap;

/**
 * Puts the linked values a filter asks about onto the entry it is judged against.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LinkedLeafWitness
{
    /**
     * @var WeakMap<FilterInterface, array<string, list<string>>>
     */
    private WeakMap $assertedCache;

    public function __construct(
        private LinkedValueLookupInterface $links,
        private LinkedAttributes $linked,
        private Schema $schema,
    ) {
        $this->assertedCache = new WeakMap();
    }

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
        // The answer depends only on the filter, so it is memoized rather than recomputed for every entry tested.
        $asserted = $this->assertedCache[$filter] ??= $this->assertedBy($filter);

        if ($asserted === []) {
            return $entry;
        }

        return $this->answering($entry, $asserted);
    }

    /**
     * @return array<string, list<string>>
     */
    private function assertedBy(FilterInterface $filter): array
    {
        $asserted = [];
        $this->collect(
            $filter,
            $asserted,
        );

        return $asserted;
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
        $value = $this->assertedValueOf(
            $filter,
            $normalized,
        );

        if ($value !== null) {
            $asserted[$normalized][] = $value;
        }
    }

    /**
     * The value the leaf asserts, or null when a linked value matching it as a DN would not answer the leaf's rule.
     */
    private function assertedValueOf(
        FilterAttributeInterface $filter,
        string $name,
    ): ?string {
        if ($filter instanceof AttributeValueAssertionInterface) {
            return $filter->getValue();
        }

        if (!$filter instanceof MatchingRuleFilter) {
            return null;
        }

        // RFC 4511 4.5.1.7.7: an extensible match is an equality match when it names no rule or the type's own.
        $rule = $filter->getMatchingRule();
        if ($rule === null) {
            return $filter->getValue();
        }
        $equality = $this->schema->getEqualityRuleOid($name);

        return $equality !== null && $this->schema->getMatchingRule($rule)?->oid === $equality
            ? $filter->getValue()
            : null;
    }
}
