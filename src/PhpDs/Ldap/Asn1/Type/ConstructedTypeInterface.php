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

/**
 * Methods representing a constructed type.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ConstructedTypeInterface
{
    /**
     * @param AbstractType[] ...$types
     * @return $this
     */
    public function setChildren(AbstractType ...$types);

    /**
     * @return AbstractType[]|ConstructedTypeInterface[]
     */
    public function getChildren() : array;

    /**
     * @param int $position
     * @return bool
     */
    public function hasChild(int $position);

    /**
     * @param int $position
     * @return AbstractType|ConstructedTypeInterface
     */
    public function getChild(int $position);

    /**
     * @param AbstractType[] ...$types
     * @return $this
     */
    public function addChild(AbstractType ...$types);
}
