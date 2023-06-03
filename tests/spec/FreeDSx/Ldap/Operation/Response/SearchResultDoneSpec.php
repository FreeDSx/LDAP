<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation\Response;

use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use PhpSpec\ObjectBehavior;

class SearchResultDoneSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(0, 'foo', 'bar');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(SearchResultDone::class);
    }

    public function it_should_extend_ldap_result(): void
    {
        $this->shouldBeAnInstanceOf(LdapResult::class);
    }
}
