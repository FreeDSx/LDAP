<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Asn1\Type;

use FreeDSx\Ldap\Exception\InvalidArgumentException;

/**
 * Implements the ConstructedTypeInterface.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait ConstructedTypeTrait
{
    /**
     * @var AbstractType[]
     */
    protected $children = [];

    /**
     * @param AbstractType[] ...$types
     */
    public function __construct(AbstractType ...$types)
    {
        $this->setChildren(...$types);
    }

    /**
     * @param int $index
     * @return bool
     */
    public function hasChild(int $index)
    {
        return isset($this->children[$index]);
    }

    /**
     * @param AbstractType[] ...$types
     * @return $this
     */
    public function setChildren(AbstractType ...$types)
    {
        $this->children = $types;

        return $this;
    }

    /**
     * @return AbstractType[]
     */
    public function getChildren() : array
    {
        return $this->children;
    }

    /**
     * @param int $index
     * @return null|AbstractType
     * @throws InvalidArgumentException
     */
    public function getChild(int $index) : ?AbstractType
    {
        return $this->children[$index] ?? null;
    }

    /**
     * @param AbstractType[] ...$types
     * @return $this
     */
    public function addChild(AbstractType ...$types)
    {
        foreach ($types as $type) {
            $this->children[] = $type;
        }

        return $this;
    }

    /**
     * @return int
     */
    public function count()
    {
        return count($this->children);
    }
}
