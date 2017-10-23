<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\PhpDs\Ldap\Operation\Response;

use PhpDs\Ldap\Asn1\Asn1;
use PhpDs\Ldap\Operation\Response\SearchResultReference;
use PhpDs\Ldap\Operation\Referral;
use PhpSpec\ObjectBehavior;

class SearchResultReferenceSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new Referral('foo'), new Referral('bar'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SearchResultReference::class);
    }

    function it_should_get_the_referrals()
    {
        $this->getReferrals()->shouldBeLike([
            new Referral('foo'),
            new Referral('bar')
        ]);
    }

    function it_should_be_constructed_from_asn1()
    {
        $this->beConstructedThrough('fromAsn1', [Asn1::application(19, Asn1::sequenceOf(
            Asn1::ldapString('foo'),
            Asn1::ldapString('bar')
        ))]);

        $this->getReferrals()->shouldBeLike([
            new Referral('foo'),
            new Referral('bar')
        ]);
    }
}
