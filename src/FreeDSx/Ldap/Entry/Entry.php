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

namespace FreeDSx\Ldap\Entry;

use ArrayIterator;
use Countable;
use IteratorAggregate;
use Stringable;
use Traversable;
use function count;
use function is_array;
use function array_map;

/**
 * Represents an Entry in LDAP.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Entry implements IteratorAggregate, Countable, Stringable
{
    private array $attributes;

    private Dn $dn;

    private Changes $changes;

    public function __construct(
        Dn|string $dn,
        Attribute ...$attributes
    ) {
        $this->dn = $dn instanceof Dn ? $dn : new Dn($dn);
        $this->attributes = $attributes;
        $this->changes = new Changes();
    }

    /**
     * Add an attribute and its values.
     */
    public function add(
        Attribute|string $attribute,
        Stringable|string ...$values
    ): static {
        $attribute = $attribute instanceof Attribute
            ? $attribute
            : new Attribute(
                $attribute,
                ...array_map(
                    fn(Stringable|string $value) => $value instanceof Stringable ? (string) $value : $value,
                    $values
                )
            );

        if (($exists = $this->get($attribute, true)) !== null) {
            $exists->add(...$attribute->getValues());
        } else {
            $this->attributes[] = $attribute;
        }
        $this->changes->add(Change::add(clone $attribute));

        return $this;
    }

    /**
     * Remove an attribute's value(s).
     */
    public function remove(
        Attribute|string $attribute,
        Stringable|string ...$values
    ): static {
        $attribute = $attribute instanceof Attribute
            ? $attribute
            : new Attribute(
                $attribute,
                ...array_map(
                    fn(Stringable|string $value) => $value instanceof Stringable ? (string) $value : $value,
                    $values
                )
            );

        if (count($attribute->getValues()) !== 0) {
            if (($exists = $this->get($attribute, true)) !== null) {
                $exists->remove(...$attribute->getValues());
            }
            $this->changes->add(Change::delete(clone $attribute));
        }

        return $this;
    }

    /**
     * Reset an attribute, which removes any values it may have.
     */
    public function reset(Attribute|string ...$attributes): static
    {
        foreach ($attributes as $attribute) {
            $attribute = $attribute instanceof Attribute ? $attribute : new Attribute($attribute);
            foreach ($this->attributes as $i => $attr) {
                if ($attr->equals($attribute, true)) {
                    unset($this->attributes[$i]);
                    break;
                }
            }
            $this->changes()->add(Change::reset(clone $attribute));
        }

        return $this;
    }

    /**
     * Set an attribute on the entry, replacing any value(s) that may exist on it.
     */
    public function set(
        Attribute|string $attribute,
        Stringable|string ...$values
    ): static {
        $attribute = $attribute instanceof Attribute
            ? $attribute
            : new Attribute(
                $attribute,
                ...array_map(
                    fn(Stringable|string $value) => $value instanceof Stringable ? (string) $value : $value,
                    $values
                )
            );

        $exists = false;
        foreach ($this->attributes as $i => $attr) {
            if ($attr->equals($attribute, true)) {
                $exists = true;
                $this->attributes[$i] = $attribute;
                break;
            }
        }
        if (!$exists) {
            $this->attributes[] = $attribute;
        }
        $this->changes->add(Change::replace(clone $attribute));

        return $this;
    }

    /**
     * Get a specific attribute by name (or Attribute object).
     *
     * @param bool $strict If set to true, then options on the attribute must also match.
     */
    public function get(
        Attribute|string $attribute,
        bool $strict = false
    ): ?Attribute {
        $attribute = $attribute instanceof Attribute ? $attribute : new Attribute($attribute);

        foreach ($this->attributes as $attr) {
            if ($attr->equals($attribute, $strict)) {
                return $attr;
            }
        }

        return null;
    }

    /**
     * Check if a specific attribute exists on the entry.
     */
    public function has(
        Attribute|string $attribute,
        bool $strict = false
    ): bool {
        $attribute = $attribute instanceof Attribute
            ? $attribute
            : new Attribute($attribute);

        return (bool) $this->get(
            $attribute,
            $strict
        );
    }

    /**
     * @return Attribute[]
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    public function getDn(): Dn
    {
        return $this->dn;
    }

    /**
     * Get the changes accumulated for this entry.
     */
    public function changes(): Changes
    {
        return $this->changes;
    }

    /**
     * Get the entry representation as an associative array.
     *
     * @return array<string, string[]>
     */
    public function toArray(): array
    {
        $attributes = [];

        foreach ($this->attributes as $attribute) {
            $attributes[$attribute->getDescription()] = $attribute->getValues();
        }

        // PHPStan sees the attribute value as mixed due to splatting. However, it can realistically never be mixed.
        /** @phpstan-ignore-next-line */
        return $attributes;
    }

    /**
     * @inheritDoc
     *
     * @return Traversable<Attribute>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->attributes);
    }

    /**
     * @psalm-return 0|positive-int
     */
    public function count(): int
    {
        return count($this->attributes);
    }

    public function __toString(): string
    {
        return $this->dn->toString();
    }

    public function __get(string $name): ?Attribute
    {
        return $this->get($name);
    }

    public function __set(string $name, Stringable|string|array $value): void
    {
        $this->set(
            $name,
            ...(is_array($value) ? $value : [(string) $value])
        );
    }

    public function __isset(string $name): bool
    {
        return $this->has($name);
    }

    public function __unset(string $name): void
    {
        $this->reset($name);
    }

    /**
     * An alias of fromArray().
     *
     * @param array<string, string|array> $attributes
     */
    public static function create(
        Dn|Stringable|string $dn,
        array $attributes = []
    ): Entry {
        return self::fromArray(
            (string) $dn,
            $attributes
        );
    }

    /**
     * Construct an entry from an associative array.
     *
     * @param array<string, string|array<string|Stringable>> $attributes
     */
    public static function fromArray(
        Dn|Stringable|string $dn,
        array             $attributes = []
    ): Entry {
        /** @var Attribute[] $entryAttr */
        $entryAttr = [];

        foreach ($attributes as $attribute => $attribute_values) {
            $entryAttr[] = new Attribute(
                $attribute,
                ...(is_array($attribute_values)
                    ? array_map(
                          fn($value) => (string) $value,
                          $attribute_values,
                      )
                    : [(string) $attribute_values]
                )
            );
        }

        return new self(
            (string) $dn,
            ...$entryAttr
        );
    }
}
