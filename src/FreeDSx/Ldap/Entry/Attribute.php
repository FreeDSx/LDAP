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

use ArrayIterator;
use Countable;
use IteratorAggregate;
use Stringable;
use Traversable;
use function array_keys;
use function array_search;
use function array_shift;
use function array_values;
use function count;
use function explode;
use function implode;
use function str_replace;
use function strpos;
use function strtolower;

/**
 * Represents an entry attribute and any values.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Attribute implements IteratorAggregate, Countable, Stringable
{
    use EscapeTrait;

    private const ESCAPE_MAP = [
        '\\' => '\5c',
        '*' => '\2a',
        '(' => '\28',
        ')' => '\29',
        "\x00" => '\00',
    ];

    private string $attribute;

    private ?string $lcAttribute = null;

    /**
     * @var string[]
     */
    private array $values;

    private ?Options $options = null;

    public function __construct(
        string $attribute,
        string ...$values
    ) {
        $this->attribute = $attribute;
        $this->values = $values;
    }

    /**
     * Add a value, or values, to the attribute.
     */
    public function add(string ...$values): self
    {
        foreach ($values as $value) {
            $this->values[] = $value;
        }

        return $this;
    }

    /**
     * Check if the attribute has a specific value.
     */
    public function has(string $value): bool
    {
        return in_array(
            $value,
            $this->values,
            true
        );
    }

    /**
     * Remove a specific value, or values, from an attribute.
     */
    public function remove(string ...$values): self
    {
        foreach ($values as $value) {
            if (($i = array_search($value, $this->values, true)) !== false) {
                unset($this->values[$i]);
            }
        }

        return $this;
    }

    /**
     * Resets the values to any empty array.
     */
    public function reset(): self
    {
        $this->values = [];

        return $this;
    }

    /**
     * Set the values for the attribute.
     */
    public function set(string ...$values): self
    {
        $this->values = $values;

        return $this;
    }

    /**
     * Gets the name (AttributeType) portion of the AttributeDescription, which excludes the options.
     */
    public function getName(): string
    {
        $this->options();

        return $this->attribute;
    }

    /**
     * Gets the full AttributeDescription (RFC 4512, 2.5), which contains the attribute type (name) and options.
     */
    public function getDescription(): string
    {
        return $this->getName()
            . ($this->options()->count() > 0 ? ';' . $this->options()->toString() : '');
    }

    /**
     * Gets any values associated with the attribute.
     *
     * @return array<string>
     */
    public function getValues(): array
    {
        return $this->values;
    }

    /**
     * Retrieve the first value of the attribute.
     */
    public function firstValue(): ?string
    {
        return $this->values[0] ?? null;
    }

    /**
     * Retrieve the last value of the attribute.
     */
    public function lastValue(): ?string
    {
        $last = end($this->values);
        reset($this->values);

        return $last === false
            ? null
            : $last;
    }

    /**
     * Gets the options within the AttributeDescription (semi-colon separated list of options).
     */
    public function getOptions(): Options
    {
        return $this->options();
    }

    public function hasOptions(): bool
    {
        return ($this->options()->count() > 0);
    }

    /**
     * {@inheritDoc}
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->values);
    }

    /**
     * {@inheritDoc}
     */
    public function count(): int
    {
        return count($this->values);
    }

    /**
     * @param bool $strict If set to true, then options must also match.
     */
    public function equals(
        Attribute $attribute,
        bool $strict = false
    ): bool {
        $this->options();
        $attribute->options();
        if ($this->lcAttribute === null) {
            $this->lcAttribute = strtolower($this->attribute);
        }
        if ($attribute->lcAttribute === null) {
            $attribute->lcAttribute = strtolower($attribute->attribute);
        }
        $nameMatches = ($this->lcAttribute === $attribute->lcAttribute);

        # Only the name of the attribute is checked for by default.
        # If strict is selected, or the attribute to be checked has explicit options, then the opposing attribute must too
        if ($strict || $attribute->hasOptions()) {
            return $nameMatches
                && ($this->getOptions()->toString(sortedlc: true) === $attribute->getOptions()->toString(sortedlc: true));
        }

        return $nameMatches;
    }

    public function __toString(): string
    {
        return implode(', ', $this->values);
    }

    /**
     * Escape an attribute value for a filter.
     */
    public static function escape(string $value): string
    {
        if (self::shouldNotEscape($value)) {
            return $value;
        }
        $value = str_replace(array_keys(self::ESCAPE_MAP), array_values(self::ESCAPE_MAP), $value);

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
        if (!str_contains($this->attribute, ';')) {
            $this->options = new Options();

            return $this->options;
        }
        $options = explode(';', $this->attribute);
        $this->attribute = (string) array_shift($options);
        $this->options = new Options(...$options);

        return $this->options;
    }
}
