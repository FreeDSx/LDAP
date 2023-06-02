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
use function count;
use function sort;

/**
 * Represents a collection of attribute options.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Options implements Countable, IteratorAggregate, Stringable
{
    /**
     * @var Option[]
     */
    private array $options;

    public function __construct(string|Option ...$options)
    {
        $this->set(...$options);
    }

    public function add(string|Option ...$options): self
    {
        foreach ($options as $option) {
            $this->options[] = $option instanceof Option ? $option : new Option($option);
        }

        return $this;
    }

    public function set(string|Option ...$options): self
    {
        $this->options = [];
        foreach ($options as $i => $option) {
            if ($option instanceof Option) {
                $this->options[] = $option;
            } else {
                $this->options[] = new Option($option);
            }
        }

        return $this;
    }

    public function has(string|Option $option): bool
    {
        $option = $option instanceof Option ? $option : new Option($option);

        foreach ($this->options as $opt) {
            if ($opt->equals($option)) {
                return true;
            }
        }

        return false;
    }

    public function remove(string|Option ...$options): self
    {
        foreach ($options as $option) {
            $option = $option instanceof Option ? $option : new Option($option);
            foreach ($this->options as $i => $opt) {
                if ($opt->equals($option)) {
                    unset($this->options[$i]);
                }
            }
        }

        return $this;
    }

    /**
     * Retrieve the first option, if it exists.
     */
    public function first(): ?Option
    {
        $option = reset($this->options);

        return $option === false ? null : $option;
    }

    /**
     * Retrieve the last option, if it exists.
     */
    public function last(): ?Option
    {
        $option = end($this->options);
        reset($this->options);

        return $option === false ? null : $option;
    }

    /**
     * @param bool $sortedlc Used for comparison, as both case and order of options are irrelevant for options equality.
     */
    public function toString(bool $sortedlc = false): string
    {
        $opts = $this->options;
        if ($sortedlc) {
            sort($opts);
        }

        $options = '';
        foreach ($opts as $option) {
            $options .= ($options === '') ? $option->toString($sortedlc) : ';' . $option->toString($sortedlc);
        }

        return $options;
    }

    /**
     * @return Option[]
     */
    public function toArray(): array
    {
        return $this->options;
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * @inheritDoc
     * @return Traversable<Option>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->options);
    }

    /**
     * @inheritDoc
     * @psalm-return 0|positive-int
     */
    public function count(): int
    {
        return count($this->options);
    }
}
