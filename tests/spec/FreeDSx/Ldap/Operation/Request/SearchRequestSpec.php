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
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Search\Result\ReferralResult;
use PhpSpec\ObjectBehavior;

class SearchRequestSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(new EqualityFilter('cn', 'foo'));
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(SearchRequest::class);
    }

    public function it_should_set_the_attributes(): void
    {
        $this->getAttributes()->shouldBeEqualTo([]);
        $this->setAttributes(new Attribute('foo'))->getAttributes()->shouldBeLike([new Attribute('foo')]);
    }

    public function it_should_set_the_attributes_using_simple_string_values(): void
    {
        $this->setAttributes('foo', 'bar');
        $this->getAttributes()->shouldBeLike([new Attribute('foo'), new Attribute('bar')]);
    }

    public function it_should_set_the_base_dn(): void
    {
        $this->getBaseDn()->shouldBeNull();
        $this->setBaseDn('dc=foo')->getBaseDn()->shouldBeLike(new Dn('dc=foo'));
    }

    public function it_should_set_the_scope(): void
    {
        $this->getScope()->shouldBeEqualTo(SearchRequest::SCOPE_WHOLE_SUBTREE);
        $this->setScope(SearchRequest::SCOPE_BASE_OBJECT)->getScope()->shouldBeEqualTo(SearchRequest::SCOPE_BASE_OBJECT);
    }

    public function it_should_set_whether_or_not_to_dereference_aliases(): void
    {
        $this->getDereferenceAliases()->shouldBeEqualTo(SearchRequest::DEREF_NEVER);
        $this->setDereferenceAliases(SearchRequest::DEREF_ALWAYS)->getDereferenceAliases()->shouldBeEqualTo(SearchRequest::DEREF_ALWAYS);
    }

    public function it_should_set_a_size_limit(): void
    {
        $this->getSizeLimit()->shouldBeEqualTo(0);
        $this->setSizeLimit(100)->getSizeLimit()->shouldBeEqualTo(100);
    }

    public function it_should_set_a_time_limit(): void
    {
        $this->getTimeLimit()->shouldBeEqualTo(0);
        $this->setTimeLimit(10)->getTimeLimit()->shouldBeEqualTo(10);
    }

    public function it_should_set_whether_or_not_to_get_attributes_only(): void
    {
        $this->getAttributesOnly()->shouldBeEqualTo(false);
        $this->setAttributesOnly(true)->getAttributesOnly()->shouldBeEqualTo(true);
    }

    public function it_should_have_an_alias_for_set_attributes_called_select(): void
    {
        $this->select('foo', 'bar')->getAttributes()->shouldBeLike([new Attribute('foo'), new Attribute('bar')]);
    }

    public function it_should_have_an_alias_for_setBaseDn_called_base(): void
    {
        $this->base('dc=foo')->getBaseDn()->shouldBeLike(new Dn('dc=foo'));
    }

    public function it_should_have_a_method_to_set_the_scopes(): void
    {
        $this->useSubtreeScope()->getScope()->shouldBeEqualTo(SearchRequest::SCOPE_WHOLE_SUBTREE);
        $this->useBaseScope()->getScope()->shouldBeEqualTo(SearchRequest::SCOPE_BASE_OBJECT);
        $this->useSingleLevelScope()->getScope()->shouldBeEqualTo(SearchRequest::SCOPE_SINGLE_LEVEL);
    }

    public function it_should_set_and_get_an_entry_handler(): void
    {
        $handler = fn (EntryResult $result) => $result->getEntry();

        $this->useEntryHandler($handler)
            ->shouldReturn($this);
        $this->getEntryHandler()
            ->shouldReturn($handler);
    }

    public function it_should_set_and_get_a_referral_handler(): void
    {
        $handler = fn (ReferralResult $result) => $result->getReferrals();

        $this->useReferralHandler($handler)
            ->shouldReturn($this);
        $this->getReferralHandler()
            ->shouldReturn($handler);
    }

    public function it_should_generate_correct_asn1(): void
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

    public function it_should_be_constructed_from_asn1(): void
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

    public function it_should_not_be_constructed_from_invalid_asn1(): void
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
