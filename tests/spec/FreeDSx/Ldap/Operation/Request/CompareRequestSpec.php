<?php

namespace spec\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DnRequestInterface;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use PhpSpec\ObjectBehavior;

class CompareRequestSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new Dn('dc=foo,dc=bar'), new EqualityFilter('foo', 'bar'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(CompareRequest::class);
    }

    function it_should_implement_the_DnRequestInterface()
    {
        $this->shouldImplement(DnRequestInterface::class);
    }

    function it_should_set_the_dn()
    {
        $this->getDn()->shouldBeLike(new Dn('dc=foo,dc=bar'));
        $this->setDn('dc=foobar')->getDn()->shouldBeLike(new Dn('dc=foobar'));
    }

    function it_should_set_the_filter()
    {
        $this->getFilter()->shouldBeLike(new EqualityFilter('foo', 'bar'));
        $this->setFilter(new EqualityFilter('cn', 'foo'))->getFilter()->shouldBeLike(new EqualityFilter('cn', 'foo'));
    }

    function it_should_generate_correct_asn1()
    {
        $this->toAsn1()->shouldBeLike(Asn1::application(14, Asn1::sequence(
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::universal(AbstractType::TAG_TYPE_SEQUENCE, (new EqualityFilter('foo', 'bar'))->toAsn1())
        )));
    }

    function it_should_be_constructed_from_asn1()
    {
        $req = new CompareRequest('foo', new EqualityFilter('foo', 'bar'));

        $this::fromAsn1($req->toAsn1())->shouldBeLike($req);
    }

    function it_should_detect_invalid_asn1_from_asn1()
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::octetString('foo')]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence()]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(Asn1::octetString('foo'))]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(Asn1::octetString('foo'), Asn1::sequence())]);
    }
}
