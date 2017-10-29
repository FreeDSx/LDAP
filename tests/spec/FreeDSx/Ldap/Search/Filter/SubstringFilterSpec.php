<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Search\Filter;

use FreeDSx\Ldap\Asn1\Asn1;
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
            Asn1::ldapString('foo'),
            Asn1::sequenceOf(
                Asn1::context(0, Asn1::octetString('f')),
                Asn1::context(1, Asn1::octetString('o')),
                Asn1::context(1, Asn1::octetString('bar')),
                Asn1::context(2, Asn1::octetString('o'))
            )
        )));

        $this->setStartsWith(null);
        $this->toAsn1()->shouldBeLike(Asn1::context(4, Asn1::sequence(
            Asn1::ldapString('foo'),
            Asn1::sequenceOf(
                Asn1::context(1, Asn1::octetString('o')),
                Asn1::context(1, Asn1::octetString('bar')),
                Asn1::context(2, Asn1::octetString('o'))
            )
        )));

        $this->setEndsWith(null);
        $this->toAsn1()->shouldBeLike(Asn1::context(4, Asn1::sequence(
            Asn1::ldapString('foo'),
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
}
