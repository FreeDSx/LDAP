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

use FreeDSx\Ldap\Control\Ad\SdFlagsControl;
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
}
