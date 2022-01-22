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

use DateTime;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use PhpSpec\ObjectBehavior;

class PagingRequestSpec extends ObjectBehavior
{
    public function let()
    {
        $this->beConstructedWith(
            new PagingControl(100, ''),
            new SearchRequest(new EqualityFilter('foo', 'bar')),
            new ControlBag(),
            'bar',
            new DateTime('01-01-2021')
        );
    }

    public function it_should_be_true_for_is_paging_starting_before_it_has_been_processed()
    {
        $this->isPagingStart()->shouldBeEqualTo(true);
    }

    public function it_should_be_false_for_is_paging_starting_after_it_has_been_processed()
    {
        $this->markProcessed();

        $this->isPagingStart()->shouldBeEqualTo(false);
    }

    public function it_should_have_a_created_at()
    {
        $this->createdAt()->shouldBeLike(new DateTime('01-01-2021'));
    }

    public function it_should_increase_iteration_after_being_processed()
    {
        $this->markProcessed();

        $this->getIteration()->shouldBeEqualTo(2);
    }

    public function it_should_have_a_last_processed_time_when_it_is_processed()
    {
        $this->markProcessed();

        $this->lastProcessedAt()->shouldNotBeEqualTo(null);
    }

    public function it_should_have_an_initial_iteration_of_1()
    {
        $this->getIteration()->shouldBeEqualTo(1);
    }

    public function it_should_get_the_size_of_the_paging_control()
    {
        $this->getSize()->shouldBeEqualTo(100);
    }

    public function it_should_get_the_cookie_from_the_paging_control()
    {
        $this->getCookie()->shouldBeEqualTo('');
    }

    public function it_should_get_the_next_cookie()
    {
        $this->getNextCookie()->shouldBeEqualTo('bar');
    }

    public function it_should_get_the_controls()
    {
        $this->controls()->shouldBeLike(new ControlBag());
    }

    public function it_should_get_the_search_request()
    {
        $this->getSearchRequest()->shouldBeLike(new SearchRequest(new EqualityFilter('foo', 'bar')));
    }

    public function it_should_update_the_next_cookie()
    {
        $this->updateNextCookie('new');

        $this->getNextCookie()->shouldBeEqualTo('new');
    }

    public function it_should_update_the_paging_control()
    {
        $this->updatePagingControl(new PagingControl(50, 'new'));

        $this->getCookie()->shouldBeEqualTo('new');
        $this->getSize()->shouldBeEqualTo(50);
    }

    public function it_should_return_false_when_not_an_abandon_request()
    {
        $this->isAbandonRequest()->shouldBeEqualTo(false);
    }

    public function it_should_return_true_when_it_is_an_abandon_request()
    {
        $this->beConstructedWith(
            new PagingControl(0, 'foo'),
            new SearchRequest(new EqualityFilter('foo', 'bar')),
            new ControlBag(),
            'bar',
            new DateTime('01-01-2021')
        );

        $this->isAbandonRequest()->shouldBeEqualTo(true);
    }

    public function it_should_not_have_a_last_processed_time_when_it_is_not_yet_processed()
    {
        $this->lastProcessedAt()->shouldBeNull();
    }

    public function it_should_get_a_unique_id()
    {
        $this->getUniqueId()->shouldBeString();
    }

    public function it_should_get_the_criticality_of_the_control()
    {
        $this->isCritical()->shouldBeEqualTo(false);
    }
}
