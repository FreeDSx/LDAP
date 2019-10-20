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

/**
 * Represents an entry attribute and any values.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Attribute implements \IteratorAggregate, \Countable
{
    use EscapeTrait;

    protected const ESCAPE_MAP = [
        '\\' => '\5c',
        '*' => '\2a',
        '(' => '\28',
        ')' => '\29',
        "\x00" => '\00',
    ];

    /**
     * @var string
     */
    protected $attribute;

    /**
     * @var null|string
     */
    protected $lcAttribute;

    /**
     * @var mixed[]|string[]
     */
    protected $values = [];

    /**
     * @var null|Options
     */
    protected $options;

    /**
     * @param string $attribute
     * @param mixed[]|string[] ...$values
     */
    public function __construct(string $attribute, ...$values)
    {
        $this->attribute = $attribute;
        $this->values = $values;
    }

    /**
     * Add a value, or values, to the attribute.
     *
     * @param mixed[]|string[] ...$values
     * @return $this
     */
    public function add(...$values): self
    {
        foreach ($values as $value) {
            $this->values[] = $value;
        }

        return $this;
    }

    /**
     * Check if the attribute has a specific value.
     *
     * @param mixed|string $value
     * @return bool
     */
    public function has($value): bool
    {
        return \array_search($value, $this->values, true) !== false;
    }

    /**
     * Remove a specific value, or values, from an attribute.
     *
     * @param mixed[]|string[] ...$values
     * @return $this
     */
    public function remove(...$values): self
    {
        foreach ($values as $value) {
            if (($i = \array_search($value, $this->values, true)) !== false) {
                unset($this->values[$i]);
            }
        }

        return $this;
    }

    /**
     * Resets the values to any empty array.
     *
     * @return $this
     */
    public function reset(): self
    {
        $this->values = [];

        return $this;
    }

    /**
     * Set the values for the attribute.
     *
     * @param mixed[]|string[] ...$values
     * @return $this
     */
    public function set(...$values): self
    {
        $this->values = $values;

        return $this;
    }

    /**
     * Gets the name (AttributeType) portion of the AttributeDescription, which excludes the options.
     *
     * @return string
     */
    public function getName(): string
    {
        $this->options();

        return $this->attribute;
    }

    /**
     * Gets the full AttributeDescription (RFC 4512, 2.5), which contains the attribute type (name) and options.
     *
     * @return string
     */
    public function getDescription(): string
    {
        return $this->getName() . ($this->options()->count() > 0 ? ';' . $this->options()->toString() : '');
    }

    /**
     * Gets any values associated with the attribute.
     *
     * @return array
     */
    public function getValues(): array
    {
        return $this->values;
    }

    /**
     * Retrieve the first value of the attribute.
     *
     * @return string|mixed|null
     */
    public function firstValue()
    {
        return $this->values[0] ?? null;
    }

    /**
     * Retrieve the last value of the attribute.
     *
     * @return string|mixed|null
     */
    public function lastValue()
    {
        $last = end($this->values);
        reset($this->values);

        return $last === false ? null : $last;
    }

    /**
     * Gets the options within the AttributeDescription (semi-colon separated list of options).
     *
     * @return Options
     */
    public function getOptions(): Options
    {
        return $this->options();
    }

    /**
     * @return bool
     */
    public function hasOptions(): bool
    {
        return ($this->options()->count() > 0);
    }

    /**
     * {@inheritDoc}
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->values);
    }

    /**
     * {@inheritDoc}
     */
    public function count(): int
    {
        return \count($this->values);
    }

    /**
     * @param Attribute $attribute
     * @param bool $strict If set to true, then options must also match.
     * @return bool
     */
    public function equals(Attribute $attribute, bool $strict = false): bool
    {
        $this->options();
        $attribute->options();
        if ($this->lcAttribute === null) {
            $this->lcAttribute = \strtolower($this->attribute);
        }
        if ($attribute->lcAttribute === null) {
            $attribute->lcAttribute = \strtolower($attribute->attribute);
        }
        $nameMatches = ($this->lcAttribute === $attribute->lcAttribute);

        # Only the name of the attribute is checked for by default.
        # If strict is selected, or the attribute to be checked has explicit options, then the opposing attribute must too
        if ($strict || $attribute->hasOptions()) {
            return $nameMatches && ($this->getOptions()->toString(true) === $attribute->getOptions()->toString(true));
        }

        return $nameMatches;
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        return \implode(', ', $this->values);
    }

    /**
     * Escape an attribute value for a filter.
     *
     * @param string $value
     * @return string
     */
    public static function escape(string $value): string
    {
        if (self::shouldNotEscape($value)) {
            return $value;
        }
        $value = \str_replace(\array_keys(self::ESCAPE_MAP), \array_values(self::ESCAPE_MAP), $value);

        return self::escapeNonPrintable($value);
    }

    /**
     * A one time check and load of any attribute options.
     */
    protected function options(): Options
    {
        if ($this->options !== null) {
            return $this->options;
        }
        if (\strpos($this->attribute, ';') === false) {
            $this->options = new Options();
            
            return $this->options;
        }
        $options = \explode(';', $this->attribute);
        $this->attribute = (string) \array_shift($options);
        $this->options = new Options(...$options);

        return $this->options;
    }
}
