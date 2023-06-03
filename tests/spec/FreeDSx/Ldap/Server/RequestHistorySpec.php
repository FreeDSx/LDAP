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

namespace spec\FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Server\Paging\PagingRequests;
use PhpSpec\ObjectBehavior;

class RequestHistorySpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(new PagingRequests());
    }

    public function it_should_add_a_valid_id(): void
    {
        $this->shouldNotThrow(ProtocolException::class)->during('addId', [1]);
    }

    public function it_should_throw_when_adding_an_existing_id(): void
    {
        $this->addId(1);

        $this->shouldThrow(ProtocolException::class)->during('addId', [1]);
    }

    public function it_should_throw_when_adding_an_invalid_id(): void
    {
        $this->shouldThrow(ProtocolException::class)->during('addId', [0]);
    }

    public function it_should_get_the_paging_requests(): void
    {
        $this->pagingRequest()->shouldBeAnInstanceOf(PagingRequests::class);
    }
}
