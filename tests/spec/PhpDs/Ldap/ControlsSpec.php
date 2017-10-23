<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\PhpDs\Ldap;

use PhpDs\Ldap\Control\Ad\SdFlagsControl;
use PhpDs\Ldap\Control\Control;
use PhpDs\Ldap\Controls;
use PhpDs\Ldap\Control\PagingControl;
use PhpDs\Ldap\Control\Vlv\VlvControl;
use PhpDs\Ldap\Search\Filters;
use PhpDs\Ldap\Search\Filter\GreaterThanOrEqualFilter;
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
}
