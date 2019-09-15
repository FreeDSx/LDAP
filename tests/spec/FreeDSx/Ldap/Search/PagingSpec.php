<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Paging;
use PhpSpec\ObjectBehavior;

class PagingSpec extends ObjectBehavior
{
    function let(LdapClient $client, SearchRequest $search)
    {
        $client->sendAndReceive($search, new PagingControl(1000, ''))->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(0, '', ''), new Entries(Entry::create('foo'), Entry::create('bar'))),
            new PagingControl(100, 'foo')
        ));

        $this->beConstructedWith($client, $search, 1000);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(Paging::class);
    }

    function it_should_check_whether_paging_has_entries_left_and_return_true_on_start()
    {
        $this->hasEntries()->shouldBeEqualTo(true);
    }

    function it_should_return_true_for_entries_when_the_cookie_is_not_empty()
    {
        $this->getEntries();
        $this->hasEntries()->shouldBeEqualTo(true);
    }

    function it_should_return_false_for_entries_when_the_cookie_is_empty($client, $search)
    {
        $client->sendAndReceive($search, new PagingControl(100, ''))->willReturn(
            new LdapMessageResponse(
                1,
                new SearchResponse(new LdapResult(0, '', ''), new Entries()),
                new PagingControl(0, '')
            )
        );
        $this->getEntries(100);

        $this->hasEntries()->shouldBeEqualTo(false);
    }

    function it_should_abort_a_paging_operation_if_end_is_called($client, $search)
    {
        $client->sendAndReceive($search, new PagingControl(0, 'foo'))->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(0, '', ''), new Entries()),
            new PagingControl(0, 'foo')
        ));

        $this->getEntries();
        $this->end();
    }

    function it_should_get_the_size_estimate_from_the_server_response()
    {
        $this->sizeEstimate()->shouldBe(null);
        $this->getEntries();
        $this->sizeEstimate()->shouldBeEqualTo(100);
    }

    function it_should_get_the_entries_from_the_response()
    {
        $this->getEntries()->shouldBeLike(new Entries(Entry::create('foo'), Entry::create('bar')));
    }
}
