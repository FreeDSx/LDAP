<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Entry;

/**
 * Represents an Entry in LDAP.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Entry implements \IteratorAggregate, \Countable
{
    /**
     * @var Attribute[]
     */
    protected $attributes;

    /**
     * @var Dn
     */
    protected $dn;

    /**
     * @param string|Dn $dn
     * @param Attribute[] ...$attributes
     */
    public function __construct($dn, Attribute ...$attributes)
    {
        $this->dn = $dn instanceof Dn ? $dn : new Dn($dn);
        $this->attributes = $attributes;
    }

    /**
     * Add an attribute (simple string or Attribute object). The values or only added if a simple string is passed.
     *
     * @param string $attribute
     * @param array ...$values
     * @return $this
     */
    public function add($attribute, ...$values)
    {
        $this->attributes[] = $attribute instanceof Attribute ? $attribute : new Attribute($attribute, ...$values);

        return $this;
    }

    /**
     * Remove an attribute (simple string or Attribute object).
     *
     * @param string|Attribute $attribute
     * @return $this
     */
    public function remove($attribute)
    {
        $attribute = $attribute instanceof Attribute ? $attribute : new Attribute($attribute);

        foreach ($this->attributes as $i => $attr) {
            if ($attr->equals($attribute)) {
                unset($this->attributes[$i]);
            }
        }

        return $this;
    }

    /**
     * Get a specific attribute by name (or Attribute object).
     *
     * @param string|Attribute $attribute
     * @return null|Attribute
     */
    public function get($attribute) : ?Attribute
    {
        $attribute = $attribute instanceof Attribute ? $attribute : new Attribute($attribute);

        foreach ($this->attributes as $attr) {
            if ($attribute->equals($attr)) {
                return $attr;
            }
        }

        return null;
    }

    /**
     * Check if a specific attribute exists on the entry.
     *
     * @param string|Attribute $attribute
     * @return bool
     */
    public function has($attribute) : bool
    {
        $attribute = $attribute instanceof Attribute ? $attribute : new Attribute($attribute);

        foreach ($this->attributes as $attr) {
            if ($attr->equals($attribute)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return Attribute[]
     */
    public function getAttributes() : array
    {
        return $this->attributes;
    }

    /**
     * @return Dn
     */
    public function getDn() : Dn
    {
        return $this->dn;
    }

    /**
     * Get the entry representation as an associative array.
     *
     * @return array
     */
    public function toArray() : array
    {
        $attributes = [];

        foreach ($this->attributes as $attribute) {
            $attributes[$attribute->getName()] = $attribute->getValues();
        }

        return $attributes;
    }

    /**
     * @return \ArrayIterator
     */
    public function getIterator()
    {
        return new \ArrayIterator($this->attributes);
    }

    /**
     * @return int
     */
    public function count()
    {
        return count($this->attributes);
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->dn->toString();
    }

    /**
     * Construct an entry from an associative array.
     *
     * @param string $dn
     * @param array $attributes
     * @return Entry
     */
    public static function create(string $dn, array $attributes = []) : Entry
    {
        /** @var Attribute[] $entryAttr */
        $entryAttr = [];

        foreach ($attributes as $attribute => $value) {
            $entryAttr[] = new Attribute($attribute, ...(is_array($value) ? $value : [$value]));
        }

        return new self($dn, ...$entryAttr);
    }
}
