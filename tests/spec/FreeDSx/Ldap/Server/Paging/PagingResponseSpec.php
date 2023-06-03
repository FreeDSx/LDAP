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

namespace spec\FreeDSx\Ldap\Server\Paging;

use FreeDSx\Ldap\Entry\Entries;
use PhpSpec\ObjectBehavior;

class PagingResponseSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(new Entries());
    }

    public function it_should_not_be_complete_by_default(): void
    {
        $this->isComplete()->shouldBeEqualTo(false);
    }

    public function it_should_have_the_size_remaining(): void
    {
        $this->getRemaining()->shouldBeEqualTo(0);
    }

    public function it_should_get_the_entries(): void
    {
        $this->getEntries()->shouldBeLike(new Entries());
    }

    public function it_should_make_a_complete_response(): void
    {
        $this->beConstructedThrough('makeFinal', [new Entries()]);

        $this->isComplete()->shouldBeEqualTo(true);
    }

    public function it_should_make_a_regular_response(): void
    {
        $this->beConstructedThrough('make', [new Entries()]);

        $this->isComplete()->shouldBeEqualTo(false);
    }
}
