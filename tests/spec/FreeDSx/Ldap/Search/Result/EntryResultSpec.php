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

namespace spec\FreeDSx\Ldap\Search\Result;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use PhpSpec\ObjectBehavior;

class EntryResultSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(
            new LdapMessageResponse(
                1,
                new SearchResultEntry(
                    new Entry('cn=foo')
                ),
            )
        );
    }

    public function it_should_get_the_entry(): void
    {
        $this->getEntry()
            ->shouldBeLike(new Entry('cn=foo'));
    }

    public function it_should_get_the_raw_message(): void
    {
        $this->getMessage()
            ->shouldBeLike(
                new LdapMessageResponse(
                    1,
                    new SearchResultEntry(
                        new Entry('cn=foo')
                    ),
                )
            );
    }

    public function it_should_have_a_string_representation_if_the_dn_of_the_entry(): void
    {
        $this->__toString()
            ->shouldBeEqualTo('cn=foo');
    }
}
