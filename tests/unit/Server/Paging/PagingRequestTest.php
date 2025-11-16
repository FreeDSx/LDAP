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

use DateTime;
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
            new PagingControl(100, ''),
            new SearchRequest(new EqualityFilter('foo', 'bar')),
            new ControlBag(),
            'bar',
            new DateTime('01-01-2021')
        );
    }

    public function test_it_should_be_true_for_is_paging_starting_before_it_has_been_processed(): void
    {
        self::assertTrue($this->subject->isPagingStart());
    }

    public function test_it_should_be_false_for_is_paging_starting_after_it_has_been_processed(): void
    {
        $this->subject->markProcessed();

        self::assertFalse($this->subject->isPagingStart());
    }

    public function test_it_should_have_a_created_at(): void
    {
        self::assertEquals(
            new DateTime('01-01-2021'),
            $this->subject->createdAt(),
        );
    }

    public function test_it_should_increase_iteration_after_being_processed(): void
    {
        $this->subject->markProcessed();

        self::assertSame(
            2,
            $this->subject->getIteration(),
        );
    }

    public function test_it_should_have_a_last_processed_time_when_it_is_processed(): void
    {
        $this->subject->markProcessed();

        self::assertNotNull($this->subject->lastProcessedAt());
    }

    public function test_it_should_have_an_initial_iteration_of_1(): void
    {
        self::assertSame(
            1,
            $this->subject->getIteration(),
        );
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

    public function test_it_should_get_the_next_cookie(): void
    {
        self::assertSame(
            'bar',
            $this->subject->getNextCookie(),
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
                'bar'
            )),
            $this->subject->getSearchRequest(),
        );
    }

    public function test_it_should_update_the_next_cookie(): void
    {
        $this->subject->updateNextCookie('new');

        self::assertSame(
            'new',
            $this->subject->getNextCookie(),
        );
    }

    public function test_it_should_update_the_paging_control(): void
    {
        $this->subject->updatePagingControl(new PagingControl(50, 'new'));

        self::assertSame(
            'new',
            $this->subject->getCookie(),
        );
        self::assertSame(
            50,
            $this->subject->getSize(),
        );
    }

    public function test_it_should_return_false_when_not_an_abandon_request(): void
    {
        self::assertFalse($this->subject->isAbandonRequest());
    }

    public function test_it_should_return_true_when_it_is_an_abandon_request(): void
    {
        $this->subject = new PagingRequest(
            new PagingControl(0, 'foo'),
            new SearchRequest(new EqualityFilter('foo', 'bar')),
            new ControlBag(),
            'bar',
            new DateTime('01-01-2021')
        );

        self::assertTrue($this->subject->isAbandonRequest());
    }

    public function test_it_should_not_have_a_last_processed_time_when_it_is_not_yet_processed(): void
    {
        self::assertNull($this->subject->lastProcessedAt());
    }

    public function test_it_should_get_a_unique_id(): void
    {
        self::assertNotEmpty($this->subject->getUniqueId());
    }

    public function test_it_should_get_the_criticality_of_the_control(): void
    {
        self::assertFalse($this->subject->isCritical());;
    }
}
