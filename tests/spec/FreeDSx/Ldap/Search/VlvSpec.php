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

use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Control\Vlv\VlvControl;
use FreeDSx\Ldap\Control\Vlv\VlvResponseControl;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Vlv;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class VlvSpec extends ObjectBehavior
{
    function let(LdapClient $client, SearchRequest $search)
    {
        $this->beConstructedWith($client, $search, 'cn');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(Vlv::class);
    }

    function it_should_accept_a_sort_key_as_a_sort_argument($client, $search)
    {
        $this->beConstructedWith($client, $search, new SortKey('foo'));

        $client->sendAndReceive(Argument::any(), Argument::any(), new SortingControl(new SortKey('foo')))->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(50, 150,0, 'foo')
        ));

        $this->getEntries();
    }

    function it_should_accept_a_sort_control_as_a_sort_argument($client, $search)
    {
        $this->beConstructedWith($client, $search, new SortingControl(new SortKey('foo'), new SortKey('bar')));

        $client->sendAndReceive(Argument::any(), Argument::any(), new SortingControl(new SortKey('foo'), new SortKey('bar')))->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(50, 150,0, 'foo')
        ));

        $this->getEntries();
    }

    function it_should_set_the_offset_using_startAt($client)
    {
        $client->sendAndReceive(Argument::any(), new VlvControl(0, 100, 1000, 0, null, null), Argument::any())->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(50, 150,0, 'foo')
        ));

        $this->startAt(1000);
        $this->getEntries();
    }

    function it_should_set_the_offset_using_moveTo($client)
    {
        $client->sendAndReceive(Argument::any(), new VlvControl(0, 100, 1000, 0, null, null), Argument::any())->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(50, 150,0, 'foo')
        ));

        $this->moveTo(1000);
        $this->getEntries();
    }

    function it_should_return_null_on_position_if_nothing_has_happened()
    {
        $this->position()->shouldBeNull();
    }

    function it_should_return_the_offset_on_a_call_to_position($client)
    {
        $client->sendAndReceive(Argument::any(), Argument::any(), Argument::any())->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(250, 150,0, 'foo')
        ));

        $this->getEntries();
        $this->position()->shouldBeEqualTo(250);
    }

    function it_should_return_the_size_of_the_list_returned_from_the_server($client)
    {
        $client->sendAndReceive(Argument::any(), Argument::any(), Argument::any())->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(0, 200,0, 'foo')
        ));

        $this->getEntries();
        $this->listSize()->shouldBeEqualTo(200);
    }

    function it_should_get_the_offset_returned_by_the_server_when_calling_list_offset($client)
    {
        $client->sendAndReceive(Argument::any(), Argument::any(), Argument::any())->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(10, 200,0, 'foo')
        ));

        $this->getEntries();
        $this->listOffset()->shouldBeEqualTo(10);
    }

    function it_should_check_if_we_are_at_the_start_of_the_list($client)
    {
        $client->sendAndReceive(Argument::any(), Argument::any(), Argument::any())->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(1, 200,0, 'foo')
        ));

        $this->isAtStartOfList()->shouldBeEqualTo(false);
        $this->getEntries();
        $this->isAtStartOfList()->shouldBeEqualTo(true);
    }

    function it_should_check_if_we_are_at_the_start_of_the_list_based_on_the_offset_and_before_value($client)
    {
        $client->sendAndReceive(Argument::any(), Argument::any(), Argument::any())->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(101, 200,0, 'foo')
        ));
        $this->beforePosition(100);
        $this->isAtStartOfList()->shouldBeEqualTo(false);
        $this->getEntries();
        $this->isAtStartOfList()->shouldBeEqualTo(true);
    }

    function it_should_check_if_we_are_at_the_end_of_the_list($client)
    {
        $client->sendAndReceive(Argument::any(), Argument::any(), Argument::any())->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(200, 200,0, 'foo')
        ));

        $this->isAtEndOfList()->shouldBeEqualTo(false);
        $this->getEntries();
        $this->isAtEndOfList()->shouldBeEqualTo(true);
    }

    function it_should_check_if_we_are_at_the_end_of_the_list_based_on_the_offset_and_after_value($client)
    {
        $client->sendAndReceive(Argument::any(), Argument::any(), Argument::any())->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(101, 200,0, 'foo')
        ));

        $this->isAtEndOfList()->shouldBeEqualTo(false);
        $this->getEntries();
        $this->isAtEndOfList()->shouldBeEqualTo(true);
    }

    function it_should_set_the_before_and_after_positions($client)
    {
        $client->sendAndReceive(Argument::any(), new VlvControl(25, 75, 1, 0), Argument::any())->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(1, 200,0, 'foo')
        ));

        $this->beforePosition(25);
        $this->afterPosition(75);
        $this->getEntries();
    }

    function it_should_indicate_the_position_as_a_percentage_if_specified($client)
    {
        $client->sendAndReceive(Argument::any(), new VlvControl(0, 100, 1, 100), Argument::any())->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(150, 200,0, 'foo')
        ));

        $this->asPercentage(true);
        $this->getEntries();
        $this->position()->shouldBeEqualTo(75);
    }

    function it_should_move_forward_as_a_percentage_if_specified($client)
    {
        $client->sendAndReceive(Argument::any(), new VlvControl(0, 100, 1, 100), Argument::any())->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(1, 200,0, 'foo')
        ));

        $client->sendAndReceive(Argument::any(), new VlvControl(0, 100, 20, 200, null, 'foo'), Argument::any())->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(20, 200,0, 'foo')
        ));

        $this->asPercentage(true);
        $this->getEntries();
        $this->position()->shouldBeEqualTo(1);
        $this->moveForward(9);
        $this->getEntries();
        $this->position()->shouldBeEqualTo(10);
        $this->listOffset()->shouldBeEqualTo(20);
    }

    function it_should_move_backward_as_a_percentage_if_specified($client)
    {
        $client->sendAndReceive(Argument::any(), new VlvControl(0, 100, 50, 100), Argument::any())->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(100, 200,0, 'foo')
        ));

        $client->sendAndReceive(Argument::any(), new VlvControl(0, 100, 80, 200, null, 'foo'), Argument::any())->shouldBeCalled()->willReturn(new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(1, '',''), new Entries()),
            new VlvResponseControl(80, 200,0, 'foo')
        ));

        $this->asPercentage(true);
        $this->startAt(50);
        $this->getEntries();
        $this->position()->shouldBeEqualTo(50);
        $this->moveBackward(10);
        $this->getEntries();
        $this->position()->shouldBeEqualTo(40);
        $this->listOffset()->shouldBeEqualTo(80);
    }
}
