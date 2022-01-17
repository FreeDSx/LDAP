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

use FreeDSx\Ldap\Entry\Entries;
use PhpSpec\ObjectBehavior;

class PagingResponseSpec extends ObjectBehavior
{
    public function let()
    {
        $this->beConstructedWith(new Entries());
    }

    public function it_should_not_be_complete_by_default()
    {
        $this->isComplete()->shouldBeEqualTo(false);
    }

    public function it_should_have_the_size_remaining()
    {
        $this->getRemaining()->shouldBeEqualTo(0);
    }

    public function it_should_get_the_entries()
    {
        $this->getEntries()->shouldBeLike(new Entries());
    }

    public function it_should_make_a_complete_response()
    {
        $this->beConstructedThrough('makeFinal', [new Entries()]);

        $this->isComplete()->shouldBeEqualTo(true);
    }

    public function it_should_make_a_regular_response()
    {
        $this->beConstructedThrough('make', [new Entries()]);

        $this->isComplete()->shouldBeEqualTo(false);
    }
}
