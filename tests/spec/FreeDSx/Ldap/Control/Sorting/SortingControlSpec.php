<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Control\Sorting;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Exception\ProtocolException;
use PhpSpec\ObjectBehavior;

class SortingControlSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new SortKey('foo'), new SortKey('bar'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SortingControl::class);
    }

    function it_should_have_the_sorting_oid()
    {
        $this->getTypeOid()->shouldBeEqualTo(Control::OID_SORTING);
    }

    function it_should_get_the_sort_keys()
    {
        $this->getSortKeys()->shouldBeLike([
           new SortKey('foo'),
           new SortKey('bar')
        ]);
    }

    function it_should_set_sort_keys()
    {
        $this->setSortKeys(new SortKey('foobar'));

        $this->getSortKeys()->shouldBeLike([new SortKey('foobar')]);
    }

    function it_should_add_sort_keys()
    {
        $key = new SortKey('foobar');
        $this->addSortKeys($key);

        $this->getSortKeys()->shouldContain($key);
    }

    function it_should_generate_correct_asn1()
    {
        $this->addSortKeys(new SortKey('foobar', true, 'bleh'));

        $encoder = new LdapEncoder();
        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::octetString(Control::OID_SORTING),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequenceOf(
                Asn1::sequence(Asn1::octetString('foo')),
                Asn1::sequence(Asn1::octetString('bar')),
                Asn1::sequence(
                    Asn1::octetString('foobar'),
                    Asn1::context(0, Asn1::octetString('bleh')),
                    Asn1::context(1, Asn1::boolean(true))
                )
            )))
        ));
    }

    function it_should_be_constructed_from_asn1()
    {
        $encoder = new LdapEncoder();
        $this::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_SORTING),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequenceOf(
                Asn1::sequence(Asn1::octetString('foo')),
                Asn1::sequence(Asn1::octetString('bar')),
                Asn1::sequence(
                    Asn1::octetString('foobar'),
                    Asn1::context(0, Asn1::octetString('bleh')),
                    Asn1::context(1, Asn1::boolean(true))
                )
            )))
        ))->setValue(null)->shouldBeLike(new SortingControl(
            new SortKey('foo'),
            new SortKey('bar'),
            new SortKey('foobar', true, 'bleh')
        ));
    }

    function it_should_throw_an_error_parsing_sorting_keys_with_no_attribute()
    {
        $encoder = new LdapEncoder();
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::octetString(Control::OID_SORTING),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequenceOf(
                Asn1::sequence(Asn1::octetString(''))
            )))
        )]);
    }

    function it_should_throw_an_error_parsing_sorting_keys_with_unexpected_values()
    {
        $encoder = new LdapEncoder();
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::octetString(Control::OID_SORTING),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequenceOf(
                Asn1::sequence(Asn1::octetString('foo'), Asn1::enumerated(1))
            )))
        )]);
    }
}
