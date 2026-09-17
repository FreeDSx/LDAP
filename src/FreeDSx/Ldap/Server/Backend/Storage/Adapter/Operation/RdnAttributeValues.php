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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Schema\Matching\EqualityComparatorResolver;
use FreeDSx\Ldap\Schema\Matching\EquivalentValues;

use function array_values;

/**
 * Keeps the values naming an entry among its attributes, matching them by each type's equality rule.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class RdnAttributeValues
{
    public function __construct(
        private EqualityComparatorResolver $equalityResolver,
    ) {}

    /**
     * Adds each RDN value the entry does not already hold. RFC 4511 §4.7 makes them part of its content.
     */
    public function merge(Entry $entry): void
    {
        $dn = $entry->getDn();

        if ($dn->toArray() === []) {
            return;
        }

        foreach ($dn->getRdn()->getAll() as $component) {
            $value = Rdn::unescape($component->getValue());
            $existing = $entry->get($component->getName());

            if ($existing === null) {
                $entry->set(new Attribute(
                    $component->getName(),
                    $value,
                ));

                continue;
            }

            if ($this->valuesEqualTo($existing, $value) === []) {
                $existing->add($value);
            }
        }
    }

    /**
     * Removes the values equal to each component of the old RDN, dropping an attribute left with none.
     */
    public function remove(
        Entry $entry,
        Rdn $oldRdn,
    ): void {
        foreach ($oldRdn->getAll() as $component) {
            $existing = $entry->get($component->getName());

            if ($existing === null) {
                continue;
            }

            $existing->removeValues($this->valuesEqualTo(
                $existing,
                Rdn::unescape($component->getValue()),
            ));

            if ($existing->getValues() === []) {
                $entry->reset($existing);
            }
        }
    }

    /**
     * @return list<string>
     */
    private function valuesEqualTo(
        Attribute $attribute,
        string $value,
    ): array {
        $held = EquivalentValues::of(
            $this->equalityResolver->for($attribute->getName()),
            $attribute->getValues(),
        );

        return array_values($held->matching($value));
    }
}
