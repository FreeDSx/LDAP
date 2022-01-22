<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Server\Paging;

use FreeDSx\Ldap\Control\Ad\SdFlagsControl;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use PhpSpec\ObjectBehavior;

class PagingRequestComparatorSpec extends ObjectBehavior
{
    public function it_compares_true_when_they_are_the_same()
    {
        $old = new PagingRequest(
            new PagingControl(100, 'foo'),
            new SearchRequest(new EqualityFilter('cn', 'foo')),
            new ControlBag(),
            'bar'
        );
        $new = new PagingRequest(
            new PagingControl(50, 'bar'),
            new SearchRequest(new EqualityFilter('cn', 'foo')),
            new ControlBag(),
            'foo'
        );

        $this->compare($old, $new)->shouldBeEqualTo(true);
    }

    public function it_compares_false_when_the_search_is_different()
    {
        $old = new PagingRequest(
            new PagingControl(100, 'foo'),
            new SearchRequest(new EqualityFilter('cn', 'foo')),
            new ControlBag(),
            'bar'
        );
        $new = new PagingRequest(
            new PagingControl(50, 'bar'),
            new SearchRequest(new EqualityFilter('cn', 'bar')),
            new ControlBag(),
            'foo'
        );

        $this->compare($old, $new)->shouldBeEqualTo(false);
    }

    public function it_compares_false_when_the_cookie_is_different()
    {
        $old = new PagingRequest(
            new PagingControl(100, 'foo'),
            new SearchRequest(new EqualityFilter('cn', 'foo')),
            new ControlBag(),
            'foo'
        );
        $new = new PagingRequest(
            new PagingControl(50, 'bar'),
            new SearchRequest(new EqualityFilter('cn', 'bar')),
            new ControlBag(),
            'foo'
        );

        $this->compare($old, $new)->shouldBeEqualTo(false);
    }

    public function it_compares_false_when_the_controls_are_different_in_count()
    {
        $old = new PagingRequest(
            new PagingControl(100, 'foo'),
            new SearchRequest(new EqualityFilter('cn', 'foo')),
            new ControlBag(new SdFlagsControl(SdFlagsControl::DACL_SECURITY_INFORMATION)),
            'bar'
        );
        $new = new PagingRequest(
            new PagingControl(50, 'bar'),
            new SearchRequest(new EqualityFilter('cn', 'foo')),
            new ControlBag(),
            'foo'
        );

        $this->compare($old, $new)->shouldBeEqualTo(false);
    }

    public function it_compares_false_when_the_paging_criticality_is_different()
    {
        $old = new PagingRequest(
            (new PagingControl(100, 'foo'))->setCriticality(true),
            new SearchRequest(new EqualityFilter('cn', 'foo')),
            new ControlBag(new SdFlagsControl(SdFlagsControl::DACL_SECURITY_INFORMATION)),
            'bar'
        );
        $new = new PagingRequest(
            new PagingControl(50, 'bar'),
            new SearchRequest(new EqualityFilter('cn', 'foo')),
            new ControlBag(),
            'foo'
        );

        $this->compare($old, $new)->shouldBeEqualTo(false);
    }

    public function it_compares_false_when_the_controls_are_different_in_value()
    {
        $old = new PagingRequest(
            new PagingControl(100, 'foo'),
            new SearchRequest(new EqualityFilter('cn', 'foo')),
            new ControlBag(new SdFlagsControl(SdFlagsControl::DACL_SECURITY_INFORMATION)),
            'bar'
        );
        $new = new PagingRequest(
            new PagingControl(50, 'bar'),
            new SearchRequest(new EqualityFilter('cn', 'foo')),
            new ControlBag(new SdFlagsControl(SdFlagsControl::SACL_SECURITY_INFORMATION)),
            'foo'
        );

        $this->compare($old, $new)->shouldBeEqualTo(false);
    }

    public function it_compares_true_when_the_controls_are_the_same_in_value()
    {
        $old = new PagingRequest(
            new PagingControl(100, 'foo'),
            new SearchRequest(new EqualityFilter('cn', 'foo')),
            new ControlBag(new SdFlagsControl(SdFlagsControl::DACL_SECURITY_INFORMATION)),
            'bar'
        );
        $new = new PagingRequest(
            new PagingControl(50, 'bar'),
            new SearchRequest(new EqualityFilter('cn', 'foo')),
            new ControlBag(new SdFlagsControl(SdFlagsControl::DACL_SECURITY_INFORMATION)),
            'foo'
        );

        $this->compare($old, $new)->shouldBeEqualTo(true);
    }
}
