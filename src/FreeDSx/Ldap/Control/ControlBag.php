<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Control;

use ArrayIterator;
use Countable;
use IteratorAggregate;
use Traversable;
use function array_search;
use function count;
use function in_array;
use function is_string;

/**
 * Represents a set of controls.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ControlBag implements IteratorAggregate, Countable
{
    /**
     * @var Control[]
     */
    private array $controls;

    public function __construct(Control ...$controls)
    {
        $this->controls = $controls;
    }

    /**
     * Check if a specific control exists by either the OID string or the Control object (strict check).
     */
    public function has(Control|string $control): bool
    {
        if (is_string($control)) {
            foreach ($this->controls as $ctrl) {
                if ($ctrl->getTypeOid() === $control) {
                    return true;
                }
            }

            return false;
        }

        return in_array($control, $this->controls, true);
    }

    /**
     * Get a control object by the string OID type. If none is found it will return null. Can check first with has.
     */
    public function get(string $oid): ?Control
    {
        foreach ($this->controls as $control) {
            if ($oid === $control->getTypeOid()) {
                return $control;
            }
        }

        return null;
    }

    /**
     * Add more controls.
     */
    public function add(Control ...$controls): self
    {
        foreach ($controls as $control) {
            $this->controls[] = $control;
        }

        return $this;
    }

    /**
     * Set the controls.
     */
    public function set(Control ...$controls): self
    {
        $this->controls = $controls;

        return $this;
    }

    /**
     * Remove controls by OID or Control object (strict check).
     */
    public function remove(Control|string ...$controls): self
    {
        foreach ($controls as $control) {
            if (is_string($control)) {
                foreach ($this->controls as $i => $ctrl) {
                    if ($ctrl->getTypeOid() === $control) {
                        unset($this->controls[$i]);
                    }
                }
            } else {
                if (($i = array_search($control, $this->controls, true)) !== false) {
                    unset($this->controls[$i]);
                }
            }
        }

        return $this;
    }

    /**
     * Remove all controls.
     */
    public function reset(): self
    {
        $this->controls = [];

        return $this;
    }

    /**
     * Get the array of Control objects.
     *
     * @return Control[]
     */
    public function toArray(): array
    {
        return $this->controls;
    }

    /**
     * @inheritDoc
     */
    public function count(): int
    {
        return count($this->controls);
    }

    /**
     * @inheritDoc
     * @return Traversable<Control>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->controls);
    }
}
