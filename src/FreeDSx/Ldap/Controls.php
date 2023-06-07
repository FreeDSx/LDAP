<?php

declare(strict_types=1);

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
use FreeDSx\Ldap\Control\SubentriesControl;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
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
     */
    public static function create(
        string $oid,
        bool $criticality = false,
        ProtocolElementInterface|AbstractType $value = null
    ): Control {
        return new Control(
            controlType: $oid,
            criticality: $criticality,
            controlValue: $value,
        );
    }

    /**
     * Creates an AD DirSync request control.
     */
    public static function dirSync(
        int $flags = DirSyncRequestControl::FLAG_INCREMENTAL_VALUES,
        string $cookie = '',
        int $maxBytes = 2147483647
    ): DirSyncRequestControl {
        return new DirSyncRequestControl(
            flags: $flags,
            cookie: $cookie,
            maxBytes: $maxBytes,
        );
    }

    /**
     * Create an AD ExpectedEntryCount control to help restrict / validate the amount of entries returned from a search.
     */
    public static function expectedEntryCount(
        int $min,
        int $max
    ): ExpectedEntryCountControl {
        return new ExpectedEntryCountControl(
            min: $min,
            max: $max,
        );
    }

    /**
     * Create an AD ExtendedDn control.
     */
    public static function extendedDn(bool $useHexFormat = false): ExtendedDnControl
    {
        return new ExtendedDnControl($useHexFormat);
    }

    /**
     * Creates a ManageDsaIt control specified in RFC 3296. Indicates that the operation is intended to manage objects
     * within the DSA (server) Information Tree.
     */
    public static function manageDsaIt(): Control
    {
        return new Control(
            Control::OID_MANAGE_DSA_IT,
            true
        );
    }


    /**
     * Create a paging control with a specific size.
     */
    public static function paging(
        int $size,
        string $cookie = ''
    ): PagingControl {
        return new PagingControl(
            size: $size,
            cookie: $cookie,
        );
    }

    /**
     * Create an AD Policy Hints control. This enforces password constraints when modifying an AD password.
     */
    public static function policyHints(bool $isEnabled = true): PolicyHintsControl
    {
        return new PolicyHintsControl($isEnabled);
    }

    /**
     * Create a password policy control.
     */
    public static function pwdPolicy(bool $criticality = true): Control
    {
        return new Control(
            controlType: Control::OID_PWD_POLICY,
            criticality: $criticality,
        );
    }

    /**
     * Create an AD Set Owner control. Pass it a string SID and use when adding objects to set the owner.
     */
    public static function setOwner(string $sid): SetOwnerControl
    {
        return new SetOwnerControl($sid);
    }

    /**
     * Create an AD Show Deleted control. This will return deleted AD entries in a search.
     */
    public static function showDeleted(): Control
    {
        return self::create(
            oid: Control::OID_SHOW_DELETED,
            criticality: true,
        );
    }

    /**
     * Create an AD Show Recycled control. This will return recycled AD entries in a search.
     */
    public static function showRecycled(): Control
    {
        return self::create(
            oid: Control::OID_SHOW_RECYCLED,
            criticality: true,
        );
    }

    /**
     * Create a server side sort with a set of SortKey objects, or simple set of attribute names.
     */
    public static function sort(SortKey|string ...$sortKeys): SortingControl
    {
        $keys = [];
        foreach ($sortKeys as $sort) {
            $keys[] = $sort instanceof SortKey ? $sort : new SortKey($sort);
        }

        return new SortingControl(...$keys);
    }

    /**
     * Creates a subentries control. Defined in RFC 3672. Used in a search request to control the visibility of entries
     * and subentries which are within scope. Non-visible entries or subentries are not returned in response to the
     * request.
     */
    public static function subentries(bool $visible = true)
    {
        return new SubentriesControl($visible);
    }

    /**
     * Create a control for a subtree delete. On a delete request this will do a recursive delete from the DN and all
     * of its children.
     */
    public static function subtreeDelete(bool $criticality = false): Control
    {
        return new Control(
            controlType: Control::OID_SUBTREE_DELETE,
            criticality: $criticality
        );
    }

    public static function syncRequest(
        ?string $cookie = null,
        int $mode = SyncRequestControl::MODE_REFRESH_ONLY
    ): SyncRequestControl {
        return new SyncRequestControl(
            $mode,
            $cookie,
        );
    }

    /**
     * Create a VLV offset based control.
     */
    public static function vlv(
        int $before,
        int $after,
        int $offset = 1,
        int $count = 0,
        ?string $contextId = null
    ): VlvControl {
        return new VlvControl(
            before: $before,
            after: $after,
            offset: $offset,
            count: $count,
            filter: null,
            contextId: $contextId,
        );
    }

    /**
     * Create a VLV filter based control.
     */
    public static function vlvFilter(
        int $before,
        int $after,
        GreaterThanOrEqualFilter $filter,
        ?string $contextId = null
    ): VlvControl {
        return new VlvControl(
            before: $before,
            after: $after,
            offset: null,
            count: null,
            filter: $filter,
            contextId: $contextId,
        );
    }

    /**
     * Create an AD SD Flags Control.
     */
    public static function sdFlags(int $flags): SdFlagsControl
    {
        return new SdFlagsControl($flags);
    }
}
