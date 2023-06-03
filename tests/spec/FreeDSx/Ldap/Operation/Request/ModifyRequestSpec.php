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

namespace spec\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\DnRequestInterface;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use PhpSpec\ObjectBehavior;

class ModifyRequestSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(
            'cn=foo,dc=foo,dc=bar',
            Change::replace('foo', 'bar'),
            Change::add('sn', 'bleep', 'blorp')
        );
    }

    public function it_should_implement_the_DnRequestInterface(): void
    {
        $this->shouldImplement(DnRequestInterface::class);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ModifyRequest::class);
    }

    public function it_should_set_the_dn(): void
    {
        $this->getDn()->shouldBeLike(new Dn('cn=foo,dc=foo,dc=bar'));

        $this->setDn(new Dn('foo'))->getDn()->shouldBeLike(new Dn('foo'));
    }

    public function it_should_set_the_changes(): void
    {
        $this->getChanges()->shouldBeLike([
            Change::replace('foo', 'bar'),
            Change::add('sn', 'bleep', 'blorp')
        ]);

        $this->setChanges(Change::delete('foo', 'bar'))->getChanges()->shouldBeLike([
            Change::delete('foo', 'bar')
        ]);
    }

    public function it_should_generate_correct_asn1(): void
    {
        $this->toAsn1()->shouldBeLike(Asn1::application(6, Asn1::sequence(
            Asn1::octetString('cn=foo,dc=foo,dc=bar'),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::enumerated(2),
                    Asn1::sequence(
                        Asn1::octetString('foo'),
                        Asn1::setOf(
                            Asn1::octetString('bar')
                        )
                    )
                ),
                Asn1::sequence(
                    Asn1::enumerated(0),
                    Asn1::sequence(
                        Asn1::octetString('sn'),
                        Asn1::setOf(
                            Asn1::octetString('bleep'),
                            Asn1::octetString('blorp')
                        )
                    )
                )
            )
        )));
    }

    public function it_should_be_constructed_from_asn1(): void
    {
        $req = new ModifyRequest(
            'foo',
            Change::add('foo', 'bar'),
            Change::delete('bar', 'foo'),
            Change::replace('foobar', 'foo')
        );

        $this::fromAsn1($req->toAsn1())->shouldBeLike(new ModifyRequest(
            'foo',
            Change::add('foo', 'bar'),
            Change::delete('bar', 'foo'),
            Change::replace('foobar', 'foo')
        ));
    }

    public function it_should_not_be_constructed_from_asn1_with_an_invalid_dn_type(): void
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::integer(1),
            Asn1::sequence()
        )]);
    }

    public function it_should_not_be_constructed_from_asn1_with_an_invalid_changelist(): void
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::set(
            Asn1::octetString('dc=foo'),
            Asn1::sequence()
        )]);
    }

    public function it_should_not_be_constructed_from_asn1_with_an_invalid_changelist_type(): void
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::integer(1),
            Asn1::sequence()
        )]);
    }

    public function it_should_not_be_constructed_from_asn1_with_invalid_attribute_values(): void
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::sequence(
                Asn1::sequence(
                    Asn1::enumerated(2),
                    Asn1::sequence(
                        Asn1::octetString('foo'),
                        Asn1::sequence(
                            Asn1::octetString('bar')
                        )
                    )
                )
            )
        )]);
    }

    public function it_should_not_be_constructed_from_asn1_without_a_partial_attribute_description(): void
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::sequence(
                Asn1::sequence(
                    Asn1::enumerated(2),
                    Asn1::sequence(
                        Asn1::setOf(
                            Asn1::octetString('bar')
                        )
                    )
                )
            )
        )]);
    }

    public function it_should_not_be_constructed_from_asn1_without_a_change_type(): void
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::sequence(
                Asn1::sequence(
                    Asn1::integer(999),
                    Asn1::sequence(
                        Asn1::setOf(
                            Asn1::octetString('bar')
                        )
                    )
                )
            )
        )]);
    }
}
