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
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Schema\Schema;

use function array_keys;
use function array_values;
use function sprintf;

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

    private ?Backlinks $reversed = null;

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
     * Whether the attribute is the reverse of a linked one.
     */
    public function isBacklink(Attribute $attribute): bool
    {
        if ($attribute->hasOptions()) {
            return false;
        }

        return $this->linkedBy($attribute->getName()) !== null;
    }

    /**
     * The linked attribute a back-link reverses. Null when it reverses none.
     */
    public function linkedBy(string $name): ?string
    {
        return $this->backlinks()->linkedBy($name);
    }

    /**
     * Which attributes reverse which linked ones.
     */
    public function backlinks(): Backlinks
    {
        return $this->reversed ??= $this->resolveBacklinks();
    }

    /**
     * Whether values live in the link table rather than on the entry.
     */
    public function heldApart(Attribute $attribute): bool
    {
        return $this->links($attribute)
            || $this->isBacklink($attribute);
    }

    /**
     * Refuses a schema no store could keep: removing an entry removes every link naming it, which would leave an
     * object class without an attribute it requires.
     *
     * @throws RuntimeException when an object class requires a linked attribute
     */
    public function assertNoneRequired(): void
    {
        foreach ($this->schema->getObjectClasses() as $objectClass) {
            foreach ($objectClass->must as $name) {
                if (!$this->links(new Attribute($name))) {
                    continue;
                }

                throw new RuntimeException(sprintf(
                    'The object class "%s" requires "%s", which is stored as links and can be emptied by a removal.',
                    $objectClass->names[0] ?? $objectClass->oid,
                    $name,
                ));
            }
        }
    }

    /**
     * Refuses a back-link no store could maintain.
     *
     * @throws RuntimeException when a back-link declaration cannot be honoured
     */
    public function assertBacklinksAreDerivable(): void
    {
        foreach ($this->schema->getAttributeTypes() as $type) {
            $forward = $type->linkedBy();

            if ($forward === null) {
                continue;
            }
            $name = $type->names[0] ?? $type->oid;

            if (!$this->links(new Attribute($forward))) {
                throw new RuntimeException(sprintf(
                    'The attribute "%s" reverses "%s", which is not stored as links.',
                    $name,
                    $forward,
                ));
            }

            if ($this->links(new Attribute($name))) {
                throw new RuntimeException(sprintf(
                    'The attribute "%s" is stored as links and cannot also reverse one.',
                    $name,
                ));
            }

            if (!$type->noUserModification) {
                throw new RuntimeException(sprintf(
                    'The attribute "%s" reverses "%s" and must be declared NO-USER-MODIFICATION.',
                    $name,
                    $forward,
                ));
            }
        }
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

    private function resolveBacklinks(): Backlinks
    {
        $reverses = [];
        $read = [];

        foreach ($this->schema->getAttributeTypes() as $type) {
            $forward = $type->linkedBy();
            if ($forward === null) {
                continue;
            }

            $linked = Attribute::normalizeName($forward);
            foreach ($type->names as $name) {
                $reverses[Attribute::normalizeName($name)] = $linked;
            }

            // Values come back under one name per type, since repeating them under every alias would only duplicate.
            $read[Attribute::normalizeName($type->names[0] ?? $type->oid)] = $linked;
        }

        return new Backlinks(
            $reverses,
            $read,
        );
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
