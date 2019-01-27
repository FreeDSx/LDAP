<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use PhpSpec\ObjectBehavior;

class AddRequestSpec extends ObjectBehavior
{
    public function let()
    {
        $this->beConstructedWith(Entry::create('cn=foo,dc=foo,dc=bar', ['cn' => 'foo']));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(AddRequest::class);
    }

    function it_should_set_entry()
    {
        $entry = Entry::create('cn=foobar,dc=foo,dc=bar', ['cn' => 'foobar']);
        $this->getEntry()->shouldBeLike(Entry::create('cn=foo,dc=foo,dc=bar', ['cn' => 'foo']));
        $this->setEntry($entry)->getEntry()->shouldBeEqualTo($entry);
    }

    function it_should_generate_correct_asn1()
    {
        $this->beConstructedWith(Entry::create('cn=foo,dc=foo,dc=bar', ['cn' => 'foo', 'sn' => ['foo', 'bar']]));

        $this->toAsn1()->shouldBeLike(Asn1::application(8, Asn1::sequence(
            Asn1::octetString('cn=foo,dc=foo,dc=bar'),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::octetString('cn'),
                    Asn1::setOf(
                        Asn1::octetString('foo')
                    )
                ),
                Asn1::sequence(
                    Asn1::octetString('sn'),
                    Asn1::setOf(
                        Asn1::octetString('foo'),
                        Asn1::octetString('bar')
                    )
                )
            )
        )));
    }

    function it_should_be_constructed_from_asn1()
    {
        $add = new AddRequest(Entry::create('cn=foo,dc=foo,dc=bar', ['cn' => 'foo', 'sn' => ['foo', 'bar']]));

        $this::fromAsn1($add->toAsn1())->shouldBeLike(new AddRequest(Entry::create('cn=foo,dc=foo,dc=bar', ['cn' => 'foo', 'sn' => ['foo', 'bar']])));
    }

    function it_should_detect_a_malformed_asn1_request()
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::octetString('foo')]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::integer(2)
        )]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::sequence(),
            Asn1::octetString('bar')
        )]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::sequence(),
            Asn1::octetString('bar')
        )]);
    }

    function it_should_detect_a_malformed_asn1_request_partial_attribute()
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::sequence(
                Asn1::sequence(
                    Asn1::octetString('foo')
                )
            )
        )]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::sequence(
                Asn1::sequence(
                    Asn1::octetString('foo'),
                    Asn1::sequence()
                )
            )
        )]);
    }
}
