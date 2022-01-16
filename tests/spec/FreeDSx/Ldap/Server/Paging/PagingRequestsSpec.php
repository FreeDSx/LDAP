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

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use PhpSpec\ObjectBehavior;

class PagingRequestsSpec extends ObjectBehavior
{
    private $pagingRequest;

    public function let()
    {
        $this->pagingRequest = new PagingRequest(
            new PagingControl(1, 'foo'),
            new SearchRequest(new EqualityFilter('cn', 'foo')),
            new ControlBag(),
            'bar'
        );

        $this->beConstructedWith([
            $this->pagingRequest,
        ]);
    }

    public function it_should_return_true_when_it_has_the_paging_request()
    {
        $this->has('bar')->shouldBeEqualTo(true);
    }

    public function it_should_return_false_when_it_does_not_have_the_paging_request()
    {
        $this->has('foo')->shouldBeEqualTo(false);
    }

    public function it_should_return_the_paging_request_when_it_exists()
    {
        $this->findByNextCookie('bar')->shouldBeEqualTo($this->pagingRequest);
    }

    public function it_should_remove_the_paging_request()
    {
        $this->remove($this->pagingRequest);

        $this->has('bar')->shouldBeEqualTo(false);
    }

    public function it_should_add_the_paging_request()
    {
        $new = new PagingRequest(
            new PagingControl(1, 'bar'),
            new SearchRequest(new EqualityFilter('cn', 'foo')),
            new ControlBag(),
            'foo'
        );
        $this->add($new);

        $this->findByNextCookie('foo')->shouldBeEqualTo($new);
    }

    public function it_should_throw_an_exception_when_the_request_does_not_exist()
    {
        $this->shouldThrow(ProtocolException::class)
            ->during('findByNextCookie', ['ohno']);
    }
}
