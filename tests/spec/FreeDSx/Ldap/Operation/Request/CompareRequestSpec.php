<?php

namespace spec\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Ldap\Asn1\Asn1;
use FreeDSx\Ldap\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
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
            Asn1::ldapDn('dc=foo,dc=bar'),
            Asn1::universal(AbstractType::TAG_TYPE_SEQUENCE, (new EqualityFilter('foo', 'bar'))->toAsn1())
        )));
    }
}
