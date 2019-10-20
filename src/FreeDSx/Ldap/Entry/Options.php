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
 * Represents a collection of attribute options.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Options implements \Countable, \IteratorAggregate
{
    /**
     * @var Option[]
     */
    protected $options;

    /**
     * @param string|Option ...$options
     */
    public function __construct(...$options)
    {
        $this->set(...$options);
    }

    /**
     * @param string|Option ...$options
     * @return $this
     */
    public function add(...$options)
    {
        foreach ($options as $option) {
            $this->options[] = $option instanceof Option ? $option : new Option($option);
        }

        return $this;
    }

    /**
     * @param string|Option ...$options
     * @return $this
     */
    public function set(...$options)
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

    /**
     * @param string|Option $option
     * @return bool
     */
    public function has($option): bool
    {
        $option = $option instanceof Option ? $option : new Option($option);

        foreach ($this->options as $opt) {
            if ($opt->equals($option)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string|Option ...$options
     * @return $this
     */
    public function remove(...$options)
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
     *
     * @return Option|null
     */
    public function first(): ?Option
    {
        $option = reset($this->options);

        return $option === false ? null : $option;
    }

    /**
     * Retrieve the last option, if it exists.
     *
     * @return Option|null
     */
    public function last(): ?Option
    {
        $option = end($this->options);
        reset($this->options);

        return $option === false ? null : $option;
    }

    /**
     * @param bool $sortedlc Used for comparison, as both case and order of options are irrelevant for options equality.
     * @return string
     */
    public function toString(bool $sortedlc = false): string
    {
        $opts = $this->options;
        if ($sortedlc) {
            \sort($opts);
        }

        $options = '';
        foreach ($opts as $option) {
            $options .= ($options === '') ? $option->toString($sortedlc) : ';' . $option->toString($sortedlc);
        }

        return $options;
    }

    /**
     * @return array
     */
    public function toArray(): array
    {
        return $this->options;
    }
    
    /**
     * @return string
     */
    public function __toString()
    {
        return $this->toString();
    }

    /**
     * @return \Traversable
     */
    public function getIterator()
    {
        return new \ArrayIterator($this->options);
    }

    /**
     * @return int
     */
    public function count()
    {
        return \count($this->options);
    }
}
