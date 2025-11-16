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

namespace Tests\Unit\FreeDSx\Ldap\Server\Paging;

use FreeDSx\Ldap\Control\Ad\SdFlagsControl;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\Paging\PagingRequestComparator;
use PHPUnit\Framework\TestCase;

final class PagingRequestComparatorTest extends TestCase
{
    private PagingRequestComparator $subject;

    protected function setUp(): void
    {
        $this->subject = new PagingRequestComparator();
    }

    public function test_it_compares_true_when_they_are_the_same(): void
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

        self::assertTrue($this->subject->compare($old, $new));
    }

    public function test_it_compares_false_when_the_search_is_different(): void
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

        self::assertFalse($this->subject->compare($old, $new));
    }

    public function test_it_compares_false_when_the_cookie_is_different(): void
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

        self::assertFalse($this->subject->compare($old, $new));
    }

    public function test_it_compares_false_when_the_controls_are_different_in_count(): void
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

        self::assertFalse($this->subject->compare($old, $new));
    }

    public function test_it_compares_false_when_the_paging_criticality_is_different(): void
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

        self::assertFalse($this->subject->compare($old, $new));
    }

    public function test_it_compares_false_when_the_controls_are_different_in_value(): void
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

        self::assertFalse($this->subject->compare($old, $new));
    }

    public function test_it_compares_true_when_the_controls_are_the_same_in_value(): void
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

        self::assertTrue($this->subject->compare($old, $new));
    }
}
