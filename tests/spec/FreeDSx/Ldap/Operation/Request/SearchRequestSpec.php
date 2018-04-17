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
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use PhpSpec\ObjectBehavior;

class SearchRequestSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new EqualityFilter('cn', 'foo'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SearchRequest::class);
    }

    function it_should_set_the_attributes()
    {
        $this->getAttributes()->shouldBeEqualTo([]);
        $this->setAttributes(new Attribute('foo'))->getAttributes()->shouldBeLike([new Attribute('foo')]);
    }

    function it_should_set_the_attributes_using_simple_string_values()
    {
        $this->setAttributes('foo', 'bar');
        $this->getAttributes()->shouldBeLike([new Attribute('foo'), new Attribute('bar')]);
    }

    function it_should_set_the_base_dn()
    {
        $this->getBaseDn()->shouldBeNull();
        $this->setBaseDn('dc=foo')->getBaseDn()->shouldBeLike(new Dn('dc=foo'));
    }

    function it_should_set_the_scope()
    {
        $this->getScope()->shouldBeEqualTo(SearchRequest::SCOPE_WHOLE_SUBTREE);
        $this->setScope(SearchRequest::SCOPE_BASE_OBJECT)->getScope()->shouldBeEqualTo(SearchRequest::SCOPE_BASE_OBJECT);
    }

    function it_should_set_whether_or_not_to_dereference_aliases()
    {
        $this->getDereferenceAliases()->shouldBeEqualTo(SearchRequest::DEREF_NEVER);
        $this->setDereferenceAliases(SearchRequest::DEREF_ALWAYS)->getDereferenceAliases()->shouldBeEqualTo(SearchRequest::DEREF_ALWAYS);
    }

    function it_should_set_a_size_limit()
    {
        $this->getSizeLimit()->shouldBeEqualTo(0);
        $this->setSizeLimit(100)->getSizeLimit()->shouldBeEqualTo(100);
    }

    function it_should_set_a_time_limit()
    {
        $this->getTimeLimit()->shouldBeEqualTo(0);
        $this->setTimeLimit(10)->getTimeLimit()->shouldBeEqualTo(10);
    }

    function it_should_set_whether_or_not_to_get_attributes_only()
    {
        $this->getAttributesOnly()->shouldBeEqualTo(false);
        $this->setAttributesOnly(true)->getAttributesOnly()->shouldBeEqualTo(true);
    }

    function it_should_have_an_alias_for_set_attributes_called_select()
    {
        $this->select('foo', 'bar')->getAttributes()->shouldBeLike([new Attribute('foo'), new Attribute('bar')]);
    }

    function it_should_have_an_alias_for_setBaseDn_called_base()
    {
        $this->base('dc=foo')->getBaseDn()->shouldBeLike(new Dn('dc=foo'));
    }

    function it_should_have_a_method_to_set_the_scopes()
    {
        $this->useSubtreeScope()->getScope()->shouldBeEqualTo(SearchRequest::SCOPE_WHOLE_SUBTREE);
        $this->useBaseScope()->getScope()->shouldBeEqualTo(SearchRequest::SCOPE_BASE_OBJECT);
        $this->useSingleLevelScope()->getScope()->shouldBeEqualTo(SearchRequest::SCOPE_SINGLE_LEVEL);
    }

    function it_should_generate_correct_asn1()
    {
        $this->setBaseDn('dc=foo,dc=bar');

        $this->toAsn1()->shouldBeLike(Asn1::application(3, Asn1::sequence(
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::enumerated(2),
            Asn1::enumerated(0),
            Asn1::integer(0),
            Asn1::integer(0),
            Asn1::boolean(false),
            (new EqualityFilter('cn', 'foo'))->toAsn1(),
            Asn1::sequenceOf()
        )));
    }

    function it_should_be_constructed_from_asn1()
    {
        $search = (new SearchRequest(new EqualityFilter('foo', 'bar'), 'cn'))
            ->base('dc,=foo,dc=bar')
            ->timeLimit(10)
            ->sizeLimit(5)
            ->useBaseScope()
            ->setAttributesOnly(true)
            ->setDereferenceAliases(2);
        $this->beConstructedThrough('fromAsn1', [$search->toAsn1()]);

        $this->getBaseDn()->shouldBeLike(new Dn('dc,=foo,dc=bar'));
        $this->getSizeLimit()->shouldBeEqualTo(5);
        $this->getTimeLimit()->shouldBeEqualTo(10);
        $this->getScope()->shouldBeEqualTo(SearchRequest::SCOPE_BASE_OBJECT);
        $this->getAttributesOnly()->shouldBeEqualTo(true);
        $this->getDereferenceAliases()->shouldBeEqualTo(2);
    }

    function it_should_not_be_constructed_from_invalid_asn1()
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::set()]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence()]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence()]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::integer(5),
            Asn1::octetString('foo')
        )]);
    }
}
