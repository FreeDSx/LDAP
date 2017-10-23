<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Asn1\Type;

use PhpDs\Ldap\Exception\InvalidArgumentException;

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
     * @return AbstractType
     * @throws InvalidArgumentException
     */
    public function getChild(int $index) : AbstractType
    {
        if (!isset($this->children[$index])) {
            throw new InvalidArgumentException(sprintf(
                'Index %s does not exist.',
                $index
            ));
        }

        return $this->children[$index];
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
}
