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

namespace FreeDSx\Ldap\Server\Backend\Storage\Schema;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Schema;

use function array_keys;
use function array_values;

/**
 * The attribute types whose values name entries, which a store keeps as links rather than in the entry itself.
 *
 * @internal used by the PDO write path, hydration and filter translators
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class LinkedAttributes
{
    /**
     * @var array<string, true>|null Lowercased names, resolved on first use since the schema is fixed after startup.
     */
    private ?array $names = null;

    public function __construct(private readonly Schema $schema) {}

    /**
     * Whether the attribute is stored as links; an option bearing form is not, since a link keys on the base name.
     */
    public function links(Attribute $attribute): bool
    {
        if ($attribute->hasOptions()) {
            return false;
        }

        return isset($this->resolved()[Attribute::normalizeName($attribute->getName())]);
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        return array_keys($this->resolved());
    }

    /**
     * A directory declaring none pays for nothing, so every caller can short circuit on this.
     */
    public function isEmpty(): bool
    {
        return $this->resolved() === [];
    }

    /**
     * The entry's linked values, keyed by lowercased name.
     *
     * @return array<string, list<string>>
     */
    public function valuesOf(Entry $entry): array
    {
        $values = [];

        foreach ($entry->getAttributes() as $attribute) {
            if (!$this->links($attribute)) {
                continue;
            }

            $values[Attribute::normalizeName($attribute->getName())] = array_values($attribute->getValues());
        }

        return $values;
    }

    /**
     * @return array<string, true>
     */
    private function resolved(): array
    {
        if ($this->names !== null) {
            return $this->names;
        }
        $names = [];

        foreach ($this->schema->getAttributeTypes() as $type) {
            if (!$type->isLinked()) {
                continue;
            }

            foreach ($type->names as $name) {
                $names[Attribute::normalizeName($name)] = true;
            }
        }

        return $this->names = $names;
    }
}
