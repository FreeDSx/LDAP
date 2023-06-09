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

namespace spec\FreeDSx\Ldap\Operation\Response;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\EntryResult;
use PhpSpec\ObjectBehavior;

class SearchResponseSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(
            new LdapResult(
                0,
                'dc=foo,dc=bar',
                'foo',
                new LdapUrl('foo')
            ),
            [
                new EntryResult(new LdapMessageResponse(
                    1,
                    new SearchResultEntry(Entry::create('foo'))
                )),
                new EntryResult(new LdapMessageResponse(
                    1,
                    new SearchResultEntry(Entry::create('bar'))
                )),
            ],
        );
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(SearchResponse::class);
    }

    public function it_should_get_the_ldap_result_values(): void
    {
        $this->getResultCode()->shouldBeEqualTo(0);
        $this->getDn()->shouldBeLike(new Dn('dc=foo,dc=bar'));
        $this->getDiagnosticMessage()->shouldBeEqualTo('foo');
        $this->getReferrals()->shouldBeLike([new LdapUrl('foo')]);
    }

    public function it_should_get_the_entries(): void
    {
        $this->getEntries()->shouldBeLike(new Entries(...[
           Entry::create('foo'),
           Entry::create('bar')
        ]));
    }
}
