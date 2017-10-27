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

use FreeDSx\Ldap\Exception\InvalidArgumentException;

/**
 * Represents a Relative Distinguished Name.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Rdn
{
    /**
     * @var string
     */
    protected $name;

    /**
     * @var string
     */
    protected $value;

    /**
     * @var Rdn[]
     */
    protected $additional = [];

    /**
     * @param string $name
     * @param string $value
     */
    public function __construct(string $name, string $value)
    {
        $this->name = $name;
        $this->value = $value;
    }

    /**
     * @return string
     */
    public function getName() : string
    {
        return $this->name;
    }

    /**
     * @return string
     */
    public function getValue() : string
    {
        return $this->value;
    }

    /**
     * @return bool
     */
    public function isMultivalued() : bool
    {
        return !empty($this->additional);
    }

    /**
     * @return string
     */
    public function toString() : string
    {
        $rdn = $this->name.'='.$this->value;

        foreach ($this->additional as $rdn) {
            $rdn .= '+'.$rdn->getName().'='.$rdn->getValue();
        }

        return $rdn;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->toString();
    }

    /**
     * @param string $rdn
     * @return Rdn
     */
    public static function create(string $rdn) : Rdn
    {
        $pieces = preg_split('/(?<!\\\\)\+/', $rdn);

        // @todo Simplify this logic somehow?
        $obj = null;
        foreach ($pieces as $piece) {
            list($name, $value) = explode('=', $piece, 2);
            if ($obj === null) {
                $obj = new self($name, $value);
            } else {
                /** @var Rdn $obj */
                $obj->additional[] = new self($name, $value);
            }
        }

        if ($obj === null) {
            throw new InvalidArgumentException(sprintf("The RDN '%s' is not valid.", $rdn));
        }

        return $obj;
    }
}
