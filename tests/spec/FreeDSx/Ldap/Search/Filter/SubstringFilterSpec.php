<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Search\Filter;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;
use PhpSpec\ObjectBehavior;

class SubstringFilterSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo', 'f', 'o', 'o', 'bar');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SubstringFilter::class);
    }

    function it_should_get_the_starts_with_value()
    {
        $this->getStartsWith()->shouldBeEqualTo('f');
        $this->setStartsWith(null)->getStartsWith()->shouldBeEqualTo(null);
    }

    function it_should_get_the_ends_with_value()
    {
        $this->getEndsWith()->shouldBeEqualTo('o');
        $this->setEndsWith(null)->getEndsWith()->shouldBeEqualTo(null);
    }

    function it_should_get_the_contains_value()
    {
        $this->getContains()->shouldBeEqualTo(['o', 'bar']);
        $this->setContains(...[])->getContains()->shouldBeEqualTo([]);
    }

    function it_should_generate_correct_asn1()
    {
        $this->toAsn1()->shouldBeLike(Asn1::context(4, Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::sequenceOf(
                Asn1::context(0, Asn1::octetString('f')),
                Asn1::context(1, Asn1::octetString('o')),
                Asn1::context(1, Asn1::octetString('bar')),
                Asn1::context(2, Asn1::octetString('o'))
            )
        )));

        $this->setStartsWith(null);
        $this->toAsn1()->shouldBeLike(Asn1::context(4, Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::sequenceOf(
                Asn1::context(1, Asn1::octetString('o')),
                Asn1::context(1, Asn1::octetString('bar')),
                Asn1::context(2, Asn1::octetString('o'))
            )
        )));

        $this->setEndsWith(null);
        $this->toAsn1()->shouldBeLike(Asn1::context(4, Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::sequenceOf(
                Asn1::context(1, Asn1::octetString('o')),
                Asn1::context(1, Asn1::octetString('bar'))
            )
        )));
    }

    function it_should_error_if_no_starts_with_ends_with_or_contains_was_supplied()
    {
        $this->setStartsWith(null);
        $this->setEndsWith(null);
        $this->setContains(...[]);

        $this->shouldThrow(RuntimeException::class)->duringToAsn1();
    }

    function it_should_be_constructed_from_asn1()
    {
        $substring = new SubstringFilter('foo', 'foo', 'bar', 'foobar', 'wee');
        $this::fromAsn1($substring->toAsn1())->shouldBeLike($substring);

        $substring = new SubstringFilter('foo', 'foo', 'bar');
        $this::fromAsn1($substring->toAsn1())->shouldBeLike($substring);

        $substring = new SubstringFilter('foo', 'foo');
        $this::fromAsn1($substring->toAsn1())->shouldBeLike($substring);

        $substring = new SubstringFilter('foo', null, 'foo');
        $this::fromAsn1($substring->toAsn1())->shouldBeLike($substring);
        $substring = new SubstringFilter('foo', null, null, 'foo', 'bar');
        $this::fromAsn1($substring->toAsn1())->shouldBeLike($substring);
    }

    function it_should_get_the_string_filter_representation()
    {
        $this->toString()->shouldBeEqualTo('(foo=f*o*bar*o)');
    }

    function it_should_get_the_filter_representation_with_a_starts_with()
    {
        $this->setStartsWith('bar');
        $this->setEndsWith(null);
        $this->setContains(...[]);

        $this->toString()->shouldBeEqualTo('(foo=bar*)');
    }

    function it_should_get_the_filter_representation_with_an_ends_with()
    {
        $this->setStartsWith(null);
        $this->setEndsWith('bar');
        $this->setContains(...[]);

        $this->toString()->shouldBeEqualTo('(foo=*bar)');
    }

    function it_should_get_a_filter_representation_with_a_start_and_end()
    {
        $this->setStartsWith('foo');
        $this->setEndsWith('bar');
        $this->setContains(...[]);

        $this->toString()->shouldBeEqualTo('(foo=foo*bar)');
    }

    function it_should_get_a_filter_representation_with_a_start_and_contains()
    {
        $this->setStartsWith('foo');
        $this->setEndsWith(null);
        $this->setContains('b','a','r');

        $this->toString()->shouldBeEqualTo('(foo=foo*b*a*r*)');
    }

    function it_should_get_a_filter_representation_with_an_end_and_contains()
    {
        $this->setStartsWith(null);
        $this->setEndsWith('foo');
        $this->setContains('b','a','r');

        $this->toString()->shouldBeEqualTo('(foo=*b*a*r*foo)');
    }

    function it_should_have_a_filter_as_a_toString_representation()
    {
        $this->__toString()->shouldBeEqualTo('(foo=f*o*bar*o)');
    }

    function it_should_escape_values_on_the_string_representation()
    {
        $this->beConstructedWith('foo', ')(bar=*5');
        $this->setStartsWith('*');
        $this->setEndsWith(')(o=*');
        $this->setContains('fo*');
        $this->toString()->shouldBeEqualTo('(foo=\2a*fo\2a*\29\28o=\2a)');
    }
}
