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

use FreeDSx\Ldap\Control\Ad\DirSyncRequestControl;
use FreeDSx\Ldap\Control\Ad\DirSyncResponseControl;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\DirSync;
use FreeDSx\Ldap\Search\Filters;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class DirSyncSpec extends ObjectBehavior
{
    protected $initialResponse;

    protected $secondResponse;

    function let(LdapClient $client)
    {
        $this->initialResponse = new LdapMessageResponse(
            0,
            new SearchResponse(new LdapResult(0), new Entries()),
            new DirSyncResponseControl(1, 0, 'foo')
        );
        $this->secondResponse = new LdapMessageResponse(
            1,
            new SearchResponse(new LdapResult(0), new Entries()),
            new DirSyncResponseControl(0, 0, 'bar')
        );

        $client->send(Argument::that(function ($search) {
            return $search->getFilter()->toString() == '(objectClass=*)';
        }), Argument::type(DirSyncRequestControl::class))->willReturn($this->initialResponse);
        $client->readOrFail('', ['defaultNamingContext'])->willReturn(new Entry('', new Attribute('defaultNamingContext', 'dc=foo,dc=bar')));

        $this->beConstructedWith($client);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(DirSync::class);
    }

    function it_should_set_the_naming_context($client)
    {
        $client->send(Argument::that(function ($search) {
            return $search->getBaseDn()->toString() == 'dc=foo';
        }), Argument::any())->shouldBeCalled()->willReturn($this->initialResponse);

        $this->useNamingContext('dc=foo')->shouldReturnAnInstanceOf(DirSync::class);
        $this->getChanges();
    }

    function it_should_set_the_filter($client)
    {
        $client->send(Argument::that(function ($search) {
            return $search->getFilter()->toString() == '(foo=bar)';
        }), Argument::any())->shouldBeCalled()->willReturn($this->initialResponse);

        $this->useFilter(Filters::equal('foo', 'bar'))->shouldReturnAnInstanceOf(DirSync::class);
        $this->getChanges();
    }

    function it_should_set_the_attributes_to_select($client)
    {
        $client->send(Argument::that(function ($search) {
            return $search->getAttributes()[0]->getName() === 'foo';
        }), Argument::any())->shouldBeCalled()->willReturn($this->initialResponse);

        $this->selectAttributes('foo')->shouldReturnAnInstanceOf(DirSync::class);
        $this->getChanges();
    }

    function it_should_set_the_incremental_values_flag($client)
    {
        $client->send(Argument::any(), Argument::that(function ($control) {
            return $control->getFlags() !== DirSyncRequestControl::FLAG_INCREMENTAL_VALUES;
        }), Argument::any())->shouldBeCalled()->willReturn($this->initialResponse);

        $this->useIncrementalValues(false)->shouldReturnAnInstanceOf(DirSync::class);
        $this->getChanges();
    }

    function it_should_object_security_flag($client)
    {
        $client->send(Argument::any(), Argument::that(function ($control) {
            return ($control->getFlags() & DirSyncRequestControl::FLAG_OBJECT_SECURITY);
        }), Argument::any())->shouldBeCalled()->willReturn($this->initialResponse);

        $this->useObjectSecurity()->shouldReturnAnInstanceOf(DirSync::class);
        $this->getChanges();
    }

    function it_should_set_ancestor_first_order($client)
    {
        $client->send(Argument::any(), Argument::that(function ($control) {
            return ($control->getFlags() & DirSyncRequestControl::FLAG_ANCESTORS_FIRST_ORDER);
        }), Argument::any())->shouldBeCalled()->willReturn($this->initialResponse);

        $this->useAncestorFirstOrder()->shouldReturnAnInstanceOf(DirSync::class);
        $this->getChanges();
    }

    function it_should_set_the_cookie($client)
    {
        $client->send(Argument::any(), Argument::that(function ($control) {
            return ($control->getCookie() === 'foo');
        }), Argument::any())->shouldBeCalled()->willReturn($this->initialResponse);

        $this->useCookie('foo')->shouldReturnAnInstanceOf(DirSync::class);
        $this->getChanges();
    }

    function it_should_get_the_cookie()
    {
        $this->getCookie()->shouldBeEqualTo('');
        $this->getChanges();
        $this->getCookie()->shouldBeEqualTo('foo');
    }

    function it_should_set_the_cookie_from_the_response_after_the_initial_query($client)
    {
        $client->send(Argument::any(), Argument::that(function ($control) {
            return ($control->getCookie() === '');
        }), Argument::any())->shouldBeCalled()->willReturn($this->initialResponse);

        $this->getChanges();

        $client->send(Argument::any(), Argument::that(function ($control) {
            return ($control->getCookie() === 'foo');
        }), Argument::any())->shouldBeCalled()->willReturn($this->secondResponse);

        $this->getChanges();
    }

    function it_should_check_the_root_dse_for_the_default_naming_context($client)
    {
        $client->readOrFail(Argument::any(), Argument::any())->shouldBeCalledOnce();

        $this->getChanges();
        $this->getChanges();
    }

    function it_should_not_check_the_root_dse_for_the_default_naming_context_if_it_was_provided($client)
    {
        $this->useNamingContext('dc=foo');
        $client->readOrFail(Argument::any(), Argument::any())->shouldNotBeCalled();

        $this->getChanges();
    }

    function it_should_return_false_for_changes_if_no_queries_have_been_made_yet()
    {
        $this->hasChanges()->shouldBeEqualTo(false);
    }

    function it_should_return_true_for_changes_if_the_dir_sync_control_indicates_there_are()
    {
        $this->getChanges();
        $this->hasChanges()->shouldBeEqualTo(true);
    }

    function it_should_return_false_for_changes_if_the_dir_sync_control_indicates_there_are_none_left($client)
    {
        $client->send(Argument::any(), Argument::that(function ($control) {
            return ($control->getCookie() === '');
        }), Argument::any())->willReturn($this->initialResponse);

        $this->getChanges();

        $client->send(Argument::any(), Argument::that(function ($control) {
            return ($control->getCookie() === 'foo');
        }), Argument::any())->willReturn($this->secondResponse);

        $this->getChanges();
        $this->hasChanges()->shouldBeEqualTo(false);
    }
}
