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
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\LessThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\LinkedValueLookupInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use WeakMap;

use function array_diff_key;

/**
 * Puts the linked values a filter asks about onto the entry it is judged against.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LinkedLeafWitness
{
    /**
     * @var WeakMap<FilterInterface, array{array<string, list<string>>, array<string, true>}>
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
     *
     * @param array<string, true> $withheld Lowercased types left as the entry shows them.
     */
    public function witness(
        Entry $entry,
        FilterInterface $filter,
        array $withheld = [],
    ): Entry {
        if ($this->linked->isEmpty()) {
            return $entry;
        }
        // The answer depends only on the filter, so it is memoized rather than recomputed for every entry tested.
        [$asserted, $everyValue] = $this->assertedCache[$filter] ??= $this->assertedBy($filter);

        if ($withheld !== []) {
            $asserted = array_diff_key(
                $asserted,
                $withheld,
            );
        }

        if ($asserted === []) {
            return $entry;
        }

        return $this->answering(
            $entry,
            $asserted,
            $everyValue,
        );
    }

    /**
     * @return array{array<string, list<string>>, array<string, true>}
     */
    private function assertedBy(FilterInterface $filter): array
    {
        $asserted = [];
        $everyValue = [];

        $this->collect(
            $filter,
            $asserted,
            $everyValue,
        );

        return [
            $asserted,
            $everyValue,
        ];
    }

    /**
     * A copy carrying the asserted linked values as well, since a bounded read may have stopped short of them.
     *
     * @param array<string, list<string>> $asserted
     * @param array<string, true> $everyValue The names a leaf tests every value of.
     */
    private function answering(
        Entry $entry,
        array $asserted,
        array $everyValue,
    ): Entry {
        $copy = $entry->makeCopy();

        foreach ($asserted as $name => $values) {
            $held = isset($everyValue[$name])
                ? $this->everyValueOf(
                    $entry,
                    $name,
                )
                : $this->heldOf(
                    $entry,
                    $name,
                    $values,
                );

            if ($held !== []) {
                $copy->add($name, ...$held);
            }
        }

        return $copy;
    }

    /**
     * Every value the entry holds, unless it already shows all of them.
     *
     * @return list<string>
     */
    private function everyValueOf(
        Entry $entry,
        string $name,
    ): array {
        // A read capped short of every value shows the attribute only under a range option.
        if ($entry->has($name, true)) {
            return [];
        }

        return $this->links->linkValues(
            $entry->getDn(),
            $name,
        );
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
     * @param array<string, true> $everyValue
     */
    private function collect(
        FilterInterface $filter,
        array &$asserted,
        array &$everyValue,
    ): void {
        if ($filter instanceof NotFilter) {
            $this->collect(
                $filter->get(),
                $asserted,
                $everyValue,
            );

            return;
        }

        if ($filter instanceof FilterContainerInterface) {
            foreach ($filter->get() as $child) {
                $this->collect(
                    $child,
                    $asserted,
                    $everyValue,
                );
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

        if ($this->testsEveryValue($filter, $normalized)) {
            $everyValue[$normalized] = true;

            return;
        }
        $value = $this->assertedValueOf(
            $filter,
            $normalized,
        );

        if ($value !== null) {
            $asserted[$normalized][] = $value;
        }
    }

    /**
     * Whether the leaf orders the values or matches them by a rule other than equality.
     */
    private function testsEveryValue(
        FilterAttributeInterface $filter,
        string $name,
    ): bool {
        if ($filter instanceof GreaterThanOrEqualFilter || $filter instanceof LessThanOrEqualFilter) {
            return true;
        }
        if (!$filter instanceof MatchingRuleFilter || $filter->getMatchingRule() === null) {
            return false;
        }
        // No value the entry holds changes the Undefined answer an unrecognized rule gives.
        $rule = $this->schema->getMatchingRule($filter->getMatchingRule())?->oid;

        return $rule !== null
            && $rule !== $this->schema->getEqualityRuleOid($name);
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
