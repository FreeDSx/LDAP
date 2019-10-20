<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Control\Ad\DirSyncRequestControl;
use FreeDSx\Ldap\Control\Ad\ExpectedEntryCountControl;
use FreeDSx\Ldap\Control\Ad\ExtendedDnControl;
use FreeDSx\Ldap\Control\Ad\PolicyHintsControl;
use FreeDSx\Ldap\Control\Ad\SdFlagsControl;
use FreeDSx\Ldap\Control\Ad\SetOwnerControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Control\Vlv\VlvControl;
use FreeDSx\Ldap\Protocol\ProtocolElementInterface;
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;

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
     * @param AbstractType|ProtocolElementInterface|null $value
     * @return Control
     */
    public static function create(string $oid, bool $criticality = false, $value = null): Control
    {
        return new Control($oid, $criticality, $value);
    }

    /**
     * Creates an AD DirSync request control.
     *
     * @param int $flags
     * @param string $cookie
     * @param int $maxBytes
     * @return DirSyncRequestControl
     */
    public static function dirSync(int $flags = DirSyncRequestControl::FLAG_INCREMENTAL_VALUES, string $cookie = '', int $maxBytes = 2147483647)
    {
        return new DirSyncRequestControl($flags, $cookie, $maxBytes);
    }

    /**
     * Create an AD ExpectedEntryCount control to help restrict / validate the amount of entries returned from a search.
     *
     * @param int $min
     * @param int $max
     * @return ExpectedEntryCountControl
     */
    public static function expectedEntryCount(int $min, int $max): ExpectedEntryCountControl
    {
        return new ExpectedEntryCountControl($min, $max);
    }

    /**
     * Create an AD ExtendedDn control.
     *
     * @param bool $useHexFormat
     * @return ExtendedDnControl
     */
    public static function extendedDn(bool $useHexFormat = false): ExtendedDnControl
    {
        return new ExtendedDnControl($useHexFormat);
    }

    /**
     * Create a paging control with a specific size.
     *
     * @param int $size
     * @param string $cookie
     * @return PagingControl
     */
    public static function paging(int $size, string $cookie = ''): PagingControl
    {
        return new PagingControl($size, $cookie);
    }

    /**
     * Create an AD Policy Hints control. This enforces password constraints when modifying an AD password.
     *
     * @param bool $isEnabled
     * @return PolicyHintsControl
     */
    public static function policyHints(bool $isEnabled = true): PolicyHintsControl
    {
        return new PolicyHintsControl($isEnabled);
    }

    /**
     * Create a password policy control.
     *
     * @param bool $criticality
     * @return Control
     */
    public static function pwdPolicy(bool $criticality = true): Control
    {
        return new Control(Control::OID_PWD_POLICY, $criticality);
    }

    /**
     * Create an AD Set Owner control. Pass it a string SID and use when adding objects to set the owner.
     *
     * @param string $sid
     * @return SetOwnerControl
     */
    public static function setOwner(string $sid): SetOwnerControl
    {
        return new SetOwnerControl($sid);
    }

    /**
     * Create an AD Show Deleted control. This will return deleted AD entries in a search.
     *
     * @return Control
     */
    public static function showDeleted(): Control
    {
        return self::create(Control::OID_SHOW_DELETED, true);
    }

    /**
     * Create an AD Show Recycled control. This will return recycled AD entries in a search.
     *
     * @return Control
     */
    public static function showRecycled(): Control
    {
        return self::create(Control::OID_SHOW_RECYCLED, true);
    }

    /**
     * Create a server side sort with a set of SortKey objects, or simple set of attribute names.
     *
     * @param SortKey[]|string[] ...$sortKeys
     * @return SortingControl
     */
    public static function sort(...$sortKeys): SortingControl
    {
        $keys = [];
        foreach ($sortKeys as $sort) {
            $keys[] = $sort instanceof SortKey ? $sort : new SortKey($sort);
        }

        return new SortingControl(...$keys);
    }

    /**
     * Create a control for a subtree delete. On a delete request this will do a recursive delete from the DN and all
     * of its children.
     *
     * @param bool $criticality
     * @return Control
     */
    public static function subtreeDelete(bool $criticality = false): Control
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
    public static function vlv(int $before, int $after, int $offset = 1, int $count = 0, ?string $contextId = null): VlvControl
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
    public static function vlvFilter(int $before, int $after, GreaterThanOrEqualFilter $filter, ?string $contextId = null): VlvControl
    {
        return new VlvControl($before, $after, null, null, $filter, $contextId);
    }

    /**
     * Create an AD SD Flags Control.
     *
     * @param int $flags
     * @return SdFlagsControl
     */
    public static function sdFlags(int $flags): SdFlagsControl
    {
        return new SdFlagsControl($flags);
    }
}
