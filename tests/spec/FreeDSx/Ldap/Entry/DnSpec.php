<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Entry;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Rdn;
use PhpSpec\ObjectBehavior;

class DnSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('cn=fo\,o, dc=local,dc=example');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(Dn::class);
    }

    function it_should_get_all_pieces_as_an_array_of_RDNs()
    {
        $this->toArray()->shouldBeLike([
            new Rdn("cn", "fo\,o"),
            new Rdn("dc", "local"),
            new Rdn("dc", "example"),
        ]);
    }

    function it_should_get_the_parent_dn()
    {
        $this->getParent()->shouldBeLike(new Dn('dc=local,dc=example'));
    }

    function it_should_get_the_rdn()
    {
        $this->getRdn()->shouldBeLike(new Rdn('cn','fo\,o'));
    }

    function it_should_return_a_count()
    {
        $this->count()->shouldBeEqualTo(3);
    }

    function it_should_get_the_string_representation()
    {
        $this->toString()->shouldBeEqualTo('cn=fo\,o, dc=local,dc=example');
    }

    function it_should_check_if_it_is_a_valid_dn()
    {
        $this::isValid('cn=foo,dc=bar=dc=foo')->shouldBeEqualTo(true);
        $this::isValid('')->shouldBeEqualTo(true);
        $this::isValid('foo')->shouldBeEqualTo(false);
    }

    function it_should_handle_a_rootdse_as_a_dn()
    {
        $this->beConstructedWith('');

        $this->toString()->shouldBeEqualTo('');
        $this->toArray()->shouldBeEqualTo([]);
        $this->count()->shouldBeEqualTo(0);
        $this->getParent()->shouldBeNull();
    }
}
