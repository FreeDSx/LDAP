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

use PhpDs\Ldap\Entry\Dn;
use PhpDs\Ldap\Entry\Entry;
use PhpDs\Ldap\Operation\LdapResult;
use PhpDs\Ldap\Operation\Response\SearchResponse;
use PhpDs\Ldap\Operation\Referral;
use PhpSpec\ObjectBehavior;

class SearchResponseSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new LdapResult(0, 'dc=foo,dc=bar', 'foo', new Referral('foo')), Entry::create('foo'), Entry::create('bar'));
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SearchResponse::class);
    }

    function it_should_get_the_ldap_result_values()
    {
        $this->getResultCode()->shouldBeEqualTo(0);
        $this->getDn()->shouldBeLike(new Dn('dc=foo,dc=bar'));
        $this->getDiagnosticMessage()->shouldBeEqualTo('foo');
        $this->getReferrals()->shouldBeLike([new Referral('foo')]);
    }

    function it_should_get_the_entries()
    {
        $this->getEntries()->shouldBeLike([
           Entry::create('foo'),
           Entry::create('bar')
        ]);
    }
}
