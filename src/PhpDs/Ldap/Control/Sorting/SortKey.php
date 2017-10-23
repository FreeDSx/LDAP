<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Control\Sorting;

/**
 * Represents a server side sorting request SortKey.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SortKey
{
    /**
     * @var string
     */
    protected $attribute;

    /**
     * @var null|string
     */
    protected $orderingRule;

    /**
     * @var bool
     */
    protected $useReverseOrder;

    /**
     * @param string $attribute
     * @param null|string $orderingRule
     * @param bool $useReverseOrder
     */
    public function __construct(string $attribute, ?string $orderingRule = null, bool $useReverseOrder = false)
    {
        $this->attribute = $attribute;
        $this->orderingRule = $orderingRule;
        $this->useReverseOrder = $useReverseOrder;
    }

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

    /**
     * @return string
     */
    public function getOrderingRule() : ?string
    {
        return $this->orderingRule;
    }

    /**
     * @param string $orderingRule
     * @return $this
     */
    public function setOrderingRule(string $orderingRule)
    {
        $this->orderingRule = $orderingRule;

        return $this;
    }

    /**
     * @return bool
     */
    public function getUseReverseOrder() : bool
    {
        return $this->useReverseOrder;
    }

    /**
     * @param bool $useReverseOrder
     * @return $this
     */
    public function setUseReverseOrder(bool $useReverseOrder)
    {
        $this->useReverseOrder = $useReverseOrder;

        return $this;
    }
}
