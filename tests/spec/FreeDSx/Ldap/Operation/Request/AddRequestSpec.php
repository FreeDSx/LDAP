<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Ldap\Asn1\Asn1;
use FreeDSx\Ldap\Entry\Entry;
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
            Asn1::ldapDn('cn=foo,dc=foo,dc=bar'),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::ldapString('cn'),
                    Asn1::setOf(
                        Asn1::octetString('foo')
                    )
                ),
                Asn1::sequence(
                    Asn1::ldapString('sn'),
                    Asn1::setOf(
                        Asn1::octetString('foo'),
                        Asn1::octetString('bar')
                    )
                )
            )
        )));
    }
}
