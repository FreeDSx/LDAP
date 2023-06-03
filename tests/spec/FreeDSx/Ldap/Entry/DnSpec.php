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

namespace spec\FreeDSx\Ldap\Entry;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Rdn;
use PhpSpec\ObjectBehavior;

class DnSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith('cn=fo\,o, dc=local,dc=example');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(Dn::class);
    }

    public function it_should_get_all_pieces_as_an_array_of_RDNs(): void
    {
        $this->toArray()->shouldBeLike([
            new Rdn("cn", "fo\,o"),
            new Rdn("dc", "local"),
            new Rdn("dc", "example"),
        ]);
    }

    public function it_should_get_the_parent_dn(): void
    {
        $this->getParent()->shouldBeLike(new Dn('dc=local,dc=example'));
    }

    public function it_should_get_the_rdn(): void
    {
        $this->getRdn()->shouldBeLike(new Rdn('cn', 'fo\,o'));
    }

    public function it_should_return_a_count(): void
    {
        $this->count()->shouldBeEqualTo(3);
    }

    public function it_should_get_the_string_representation(): void
    {
        $this->toString()->shouldBeEqualTo('cn=fo\,o, dc=local,dc=example');
    }

    public function it_should_check_if_it_is_a_valid_dn(): void
    {
        $this::isValid('cn=foo,dc=bar=dc=foo')->shouldBeEqualTo(true);
        $this::isValid('')->shouldBeEqualTo(true);
        $this::isValid('foo')->shouldBeEqualTo(false);
    }

    public function it_should_handle_a_rootdse_as_a_dn(): void
    {
        $this->beConstructedWith('');

        $this->toString()->shouldBeEqualTo('');
        $this->toArray()->shouldBeEqualTo([]);
        $this->count()->shouldBeEqualTo(0);
        $this->getParent()->shouldBeNull();
    }
}
