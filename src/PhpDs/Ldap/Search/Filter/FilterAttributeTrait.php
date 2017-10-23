<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Search\Filter;

/**
 * Common methods for filters using attributes.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait FilterAttributeTrait
{
    /**
     * @var string
     */
    protected $attribute;

    /**
     * @return string
     */
    public function getAttribute() : string
    {
        return $this->attribute;
    }

    /**
     * @param string $attribute
     * @return $this
     */
    public function setAttribute(string $attribute)
    {
        $this->attribute = $attribute;

        return $this;
    }
}
