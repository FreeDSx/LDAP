<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap;

use FreeDSx\Ldap\Control\Ad\DirSyncRequestControl;
use FreeDSx\Ldap\Control\Ad\ExpectedEntryCountControl;
use FreeDSx\Ldap\Control\Ad\ExtendedDnControl;
use FreeDSx\Ldap\Control\Ad\PolicyHintsControl;
use FreeDSx\Ldap\Control\Ad\SdFlagsControl;
use FreeDSx\Ldap\Control\Ad\SetOwnerControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Control\Vlv\VlvControl;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;
use PhpSpec\ObjectBehavior;

class ControlsSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(Controls::class);
    }

    function it_should_create_a_paging_control()
    {
        $this->paging(100)->shouldBeLike(new PagingControl(100, ''));
    }

    function it_should_create_a_vlv_offset_control()
    {
        $this->vlv(10, 12)->shouldBeLike(new VlvControl(10, 12, 1, 0));
    }

    function it_should_create_a_vlv_filter_control()
    {
        $this->vlvFilter(10, 12, Filters::gte('foo', 'bar'))->shouldBeLike(new VlvControl(10,12, null, null, new GreaterThanOrEqualFilter('foo', 'bar')));
    }

    function it_should_create_an_sd_flags_control()
    {
        $this->sdFlags(7)->shouldBeLike(new SdFlagsControl(7));
    }

    function it_should_create_a_password_policy_control()
    {
        $this->pwdPolicy()->shouldBeLike(new Control(Control::OID_PWD_POLICY, true));
    }

    function it_should_create_a_subtree_delete_control()
    {
        $this->subtreeDelete()->shouldBeLike(new Control(Control::OID_SUBTREE_DELETE));
    }

    function it_should_create_a_sorting_control_using_a_string()
    {
        $this->sort('cn')->shouldBeLike(new SortingControl(new SortKey('cn')));
    }

    function it_should_create_a_sorting_control_using_a_sort_key()
    {
        $this->sort(new SortKey('foo'))->shouldBeLike(new SortingControl(new SortKey('foo')));
    }

    function it_should_create_an_extended_dn_control()
    {
        $this->extendedDn()->shouldBeLike(new ExtendedDnControl());
    }

    function it_should_create_a_dir_sync_control()
    {
        $this->dirSync()->shouldBeLike(new DirSyncRequestControl());
    }

    function it_should_create_a_dir_sync_control_with_options()
    {
        $this->dirSync(DirSyncRequestControl::FLAG_INCREMENTAL_VALUES|DirSyncRequestControl::FLAG_OBJECT_SECURITY, 'foo')->shouldBeLike(
            new DirSyncRequestControl(DirSyncRequestControl::FLAG_INCREMENTAL_VALUES|DirSyncRequestControl::FLAG_OBJECT_SECURITY, 'foo')
        );
    }

    function it_should_create_an_expected_entry_count_control()
    {
        $this->expectedEntryCount(1, 100)->shouldBeLike(new ExpectedEntryCountControl(1, 100));
    }

    function it_should_create_a_policy_hints_control()
    {
        $this::policyHints()->shouldBeLike(new PolicyHintsControl());
    }

    function it_should_create_a_set_owners_control()
    {
        $this::setOwner('foo')->shouldBeLike(new SetOwnerControl('foo'));
    }

    function it_should_create_a_show_deleted_control()
    {
        $this::showDeleted()->shouldBeLike(new Control(Control::OID_SHOW_DELETED, true));
    }

    function it_should_create_a_show_recycled_control()
    {
        $this::showRecycled()->shouldBeLike(new Control(Control::OID_SHOW_RECYCLED, true));
    }
}
