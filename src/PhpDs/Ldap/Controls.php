<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap;

use PhpDs\Ldap\Control\Ad\SdFlagsControl;
use PhpDs\Ldap\Control\Control;
use PhpDs\Ldap\Control\PagingControl;
use PhpDs\Ldap\Control\Sorting\SortingControl;
use PhpDs\Ldap\Control\Sorting\SortKey;
use PhpDs\Ldap\Control\Vlv\VlvControl;
use PhpDs\Ldap\Search\Filter\GreaterThanOrEqualFilter;

/**
 * Provides some simple factory methods for building controls.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Controls
{
    /**
     * Create a generic control by OID.
     *
     * @param string $oid
     * @param bool $criticality
     * @param null $value
     * @return Control
     */
    public static function create(string $oid, $criticality = false, $value = null)
    {
        return new Control($oid, $criticality, $value);
    }

    /**
     * Create a paging control with a specific size.
     *
     * @param int $size
     * @param string $cookie
     * @return PagingControl
     */
    public static function paging(int $size, $cookie = '')
    {
        return new PagingControl($size, $cookie);
    }

    /**
     * Create a password policy control.
     *
     * @param bool $criticality
     * @return Control
     */
    public static function pwdPolicy(bool $criticality = true)
    {
        return new Control(Control::OID_PWD_POLICY, $criticality);
    }

    /**
     * Create a server side sort with a set of SortKey objects, or simple set of attribute names.
     *
     * @param SortKey[]|string ...$sortKeys
     * @return SortingControl
     */
    public static function sort(...$sortKeys)
    {
        $keys = [];
        foreach ($sortKeys as $sort) {
            $keys[] = $sort instanceof SortKey ? $sort : new SortKey($sort);
        }

        return new SortingControl(...$keys);
    }

    /**
     * Create a server sort using just a simple attribute name, with an optional ordering rule and whether to reverse.
     *
     * @param string $attribute
     * @param string $orderingRule
     * @param bool $reverseOrder
     * @return SortingControl
     */
    public function simpleSort(string $attribute, string $orderingRule = '', bool $reverseOrder = false)
    {
        return new SortingControl(new SortKey($attribute, $orderingRule, $reverseOrder));
    }

    /**
     * Create a control for a subtree delete. On a delete request this will do a recursive delete from the DN and all
     * of its children.
     *
     * @param bool $criticality
     * @return Control
     */
    public static function subtreeDelete(bool $criticality = false)
    {
        return new Control(Control::OID_SUBTREE_DELETE, $criticality);
    }

    /**
     * Create a VLV offset based control.
     *
     * @param int $before
     * @param int $after
     * @param int $offset
     * @param int $count
     * @param null|string $contextId
     * @return VlvControl
     */
    public static function vlv(int $before, int $after, int $offset = 1, int $count = 0, ?string $contextId = null)
    {
        return new VlvControl($before, $after, $offset, $count, null, $contextId);
    }

    /**
     * Create a VLV filter based control.
     *
     * @param int $before
     * @param int $after
     * @param GreaterThanOrEqualFilter $filter
     * @param null|string $contextId
     * @return VlvControl
     */
    public static function vlvFilter(int $before, int $after, GreaterThanOrEqualFilter $filter, ?string $contextId = null)
    {
        return new VlvControl($before, $after, null, null, $filter, $contextId);
    }

    /**
     * Create an AD SD Flags Control.
     *
     * @param int $flags
     * @return SdFlagsControl
     */
    public static function sdFlags(int $flags)
    {
        return new SdFlagsControl($flags);
    }
}
