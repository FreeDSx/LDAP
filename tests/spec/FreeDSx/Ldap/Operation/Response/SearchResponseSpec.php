<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation\Response;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use PhpSpec\ObjectBehavior;

class SearchResponseSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith(new LdapResult(0, 'dc=foo,dc=bar', 'foo', new LdapUrl('foo')), new Entries(...[Entry::create('foo'), Entry::create('bar')]));
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
        $this->getReferrals()->shouldBeLike([new LdapUrl('foo')]);
    }

    function it_should_get_the_entries()
    {
        $this->getEntries()->shouldBeLike(new Entries(...[
           Entry::create('foo'),
           Entry::create('bar')
        ]));
    }
}
