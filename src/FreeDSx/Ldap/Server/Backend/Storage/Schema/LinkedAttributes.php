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
use FreeDSx\Ldap\Schema\Schema;

use function array_keys;

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
     * Whether the type is stored as links; options bearing forms are not, since a link keys on the base name.
     */
    public function links(string $attribute): bool
    {
        return isset($this->resolved()[Attribute::normalizeName($attribute)]);
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
