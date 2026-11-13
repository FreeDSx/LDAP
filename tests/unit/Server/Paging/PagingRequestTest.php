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

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use PHPUnit\Framework\TestCase;

final class PagingRequestTest extends TestCase
{
    private PagingRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new PagingRequest(
            new PagingControl(
                100,
                '',
            ),
            new SearchRequest(new EqualityFilter(
                'foo',
                'bar',
            )),
            new ControlBag(),
        );
    }

    public function test_it_is_a_paging_start_when_no_cookie_is_sent(): void
    {
        self::assertTrue($this->subject->isPagingStart());
    }

    public function test_it_is_not_a_paging_start_when_a_cookie_is_sent(): void
    {
        $subject = new PagingRequest(
            new PagingControl(
                100,
                'foo',
            ),
            new SearchRequest(new EqualityFilter(
                'foo',
                'bar',
            )),
            new ControlBag(),
        );

        self::assertFalse($subject->isPagingStart());
    }

    public function test_it_should_get_the_size_of_the_paging_control(): void
    {
        self::assertSame(
            100,
            $this->subject->getSize(),
        );
    }

    public function test_it_should_get_the_cookie_from_the_paging_control(): void
    {
        self::assertSame(
            '',
            $this->subject->getCookie(),
        );
    }

    public function test_it_should_get_the_controls(): void
    {
        self::assertEquals(
            new ControlBag(),
            $this->subject->controls(),
        );
    }

    public function test_it_should_get_the_search_request(): void
    {
        self::assertEquals(
            new SearchRequest(new EqualityFilter(
                'foo',
                'bar',
            )),
            $this->subject->getSearchRequest(),
        );
    }

    public function test_it_should_return_false_when_not_an_abandon_request(): void
    {
        self::assertFalse($this->subject->isAbandonRequest());
    }

    public function test_it_should_return_true_when_it_is_an_abandon_request(): void
    {
        $subject = new PagingRequest(
            new PagingControl(
                0,
                'foo',
            ),
            new SearchRequest(new EqualityFilter(
                'foo',
                'bar',
            )),
            new ControlBag(),
        );

        self::assertTrue($subject->isAbandonRequest());
    }

    public function test_it_should_get_the_criticality_of_the_control(): void
    {
        self::assertFalse($this->subject->isCritical());
    }
}
