<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Entry;

use function count;

/**
 * Represents an entry change.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Change
{
    /**
     * Add a value to an attribute.
     */
    public const TYPE_ADD = 0;

    /**
     * Delete a value, or values, from an attribute.
     */
    public const TYPE_DELETE = 1;

    /**
     * Replaces the current value of an attribute with a different one.
     */
    public const TYPE_REPLACE = 2;

    private int $modType;

    private Attribute $attribute;

    public function __construct(
        int $modType,
        Attribute|string $attribute,
        string ...$values
    ) {
        $this->modType = $modType;
        $this->attribute = $attribute instanceof Attribute
            ? $attribute
            : new Attribute($attribute, ...$values);
    }

    public function getAttribute(): Attribute
    {
        return $this->attribute;
    }

    public function setAttribute(Attribute $attribute): self
    {
        $this->attribute = $attribute;

        return $this;
    }

    public function getType(): int
    {
        return $this->modType;
    }

    public function setType(int $modType): self
    {
        $this->modType = $modType;

        return $this;
    }

    public function isAdd(): bool
    {
        return $this->modType === self::TYPE_ADD;
    }

    public function isDelete(): bool
    {
        return $this->modType === self::TYPE_DELETE && count($this->attribute->getValues()) !== 0;
    }

    public function isReplace(): bool
    {
        return $this->modType === self::TYPE_REPLACE;
    }

    public function isReset(): bool
    {
        return $this->modType === self::TYPE_DELETE
            && count($this->attribute->getValues()) === 0;
    }

    /**
     * Add the values contained in the attribute, creating the attribute if necessary.
     */
    public static function add(
        Attribute|string $attribute,
        string ...$values
    ): Change {
        $attribute = $attribute instanceof Attribute
            ? $attribute
            : new Attribute($attribute, ...$values);

        return new self(
            self::TYPE_ADD,
            $attribute
        );
    }

    /**
     * Delete values from the attribute. If no values are listed, or if all current values of the attribute are listed,
     * the entire attribute is removed.
     */
    public static function delete(
        Attribute|string $attribute,
        string ...$values
    ): Change {
        $attribute = $attribute instanceof Attribute
            ? $attribute
            : new Attribute(
                $attribute,
                ...$values
            );

        return new self(
            self::TYPE_DELETE,
            $attribute
        );
    }

    /**
     * Replace all existing values with the new values, creating the attribute if it did not already exist.  A replace
     * with no value will delete the entire attribute if it exists, and it is ignored if the attribute does not exist.
     */
    public static function replace(
        Attribute|string $attribute,
        string ...$values
    ): Change {
        $attribute = $attribute instanceof Attribute
            ? $attribute
            : new Attribute(
                $attribute,
                ...$values
            );

        return new self(
            self::TYPE_REPLACE,
            $attribute
        );
    }

    /**
     * Remove all values from an attribute, essentially un-setting/resetting it. This is the same type as delete when
     * going to LDAP. The real difference being that no values are attached to the change.
     */
    public static function reset(Attribute|string $attribute): Change
    {
        $attribute = $attribute instanceof Attribute
            ? new Attribute($attribute->getDescription())
            : new Attribute($attribute);

        return new self(
            self::TYPE_DELETE,
            $attribute
        );
    }
}
