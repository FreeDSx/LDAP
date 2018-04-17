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

    function it_should_escape_an_rdn_value_with_leading_and_trailing_spaces()
    {
        $this::escape(' foo,= bar ')->shouldBeEqualTo('\20foo\2c= bar\20');
    }

    function it_should_escape_an_rdn_value_with_a_leading_pound_sign()
    {
        $this::escape('# foo ')->shouldBeEqualTo('\23 foo\20');
    }

    function it_should_escape_required_values()
    {
        $this::escape('\foo + "bar", > bar < foo;')->shouldBeEqualTo('\5cfoo \2b \22bar\22\2c \3e bar \3c foo\3b');
    }

    function it_should_escape_all_characters()
    {
        $this::escapeAll('# foo ')->shouldBeEqualTo('\23\20\66\6f\6f\20');
    }
}
