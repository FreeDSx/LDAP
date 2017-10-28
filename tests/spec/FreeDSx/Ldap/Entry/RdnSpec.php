<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Entry;

use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use PhpSpec\ObjectBehavior;

class RdnSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('cn', 'foo');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(Rdn::class);
    }

    function it_should_get_the_name()
    {
        $this->getName()->shouldBeEqualTo('cn');
    }

    function it_should_get_the_value()
    {
        $this->getValue()->shouldBeEqualTo('foo');
    }

    function it_should_get_the_string_representation()
    {
        $this->toString()->shouldBeEqualTo('cn=foo');
    }

    function it_should_get_whether_it_is_multivalued()
    {
        $this->isMultivalued()->shouldBeEqualTo(false);
    }

    function it_should_be_created_from_a_string_rdn()
    {
        $this->beConstructedThrough('create', ['cn=foobar']);

        $this->getName()->shouldBeEqualTo('cn');
        $this->getValue()->shouldBeEqualTo('foobar');
    }

    function it_should_error_when_constructing_an_rdn_that_is_invalid()
    {
        $this->shouldThrow(InvalidArgumentException::class)->during('create', ['foobar']);
    }
}
