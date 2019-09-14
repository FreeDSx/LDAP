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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Search\RangeRetrieval;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class RangeRetrievalSpec extends ObjectBehavior
{
    function let(LdapClient $client)
    {
        $this->beConstructedWith($client);    
    }
    
    function it_is_initializable()
    {
        $this->shouldHaveType(RangeRetrieval::class);
    }
    
    function it_should_get_a_specific_ranged_attribute_from_an_entry_if_it_exists()
    {
        $this->getRanged(Entry::create('dc=foo', ['member;range=0-1500' => [], 'foo' => []]), 'member')->getName()->shouldBeEqualTo('member');
    }
    
    function it_should_return_null_on_a_request_for_a_specific_ranged_attribute_that_does_not_exist()
    {
        $this->getRanged(Entry::create('dc=foo', ['member;range=0-1500' => [], 'foo' => []]), 'bar')->shouldBeNull();
    }
    
    function it_should_get_all_ranged_attributes_for_an_entry_as_an_array()
    {
        $this->getAllRanged(Entry::create('dc=foo', ['member;range=0-1500' => [], 'foo' => [], 'bar;range=0-1000' => []]))->shouldHaveCount(2);
    }

    function it_should_return_whether_an_entry_has_an_ranged_attributes()
    {
        $this->hasRanged(Entry::create('dc=foo', ['member;range=0-1500' => [], 'foo' => []]))->shouldBeEqualTo(true);
        $this->hasRanged(Entry::create('dc=foo', ['member' => [], 'foo' => []]))->shouldBeEqualTo(false);
    }
    
    function it_should_return_whether_an_entry_has_a_specific_ranged_attribute()
    {
        $this->hasRanged(Entry::create('dc=foo', ['member;range=0-1500' => [], 'foo' => []]), 'member')->shouldBeEqualTo(true);
        $this->hasRanged(Entry::create('dc=foo', ['member;range=0-1500' => [], 'foo' => []]), 'foo')->shouldBeEqualTo(false);
    }
    
    function it_should_check_if_a_ranged_attribute_has_more_values_to_retrieve()
    {
        $this->hasMoreValues(new Attribute('member'))->shouldBeEqualTo(false);
        $this->hasMoreValues(new Attribute('member;range=0-*'))->shouldBeEqualTo(false);
    }
    
    function it_should_get_more_values_for_a_ranged_attribute($client)
    {
        $attrResult = new Attribute('member;range=1501-2000');
        $entry = new Entry('dc=foo', $attrResult);
        
        $client->readOrFail('dc=foo', Argument::that(function ($attr) {
            return $attr[0]->getOptions()->first()->getLowRange() == '1501' && $attr[0]->getOptions()->first()->getHighRange() == '*';
        }))->shouldBeCalled()->willReturn($entry);
        
        $this->getMoreValues('dc=foo', new Attribute('member;range=0-1500'))->shouldBeEqualTo($attrResult);
    }
    
    function it_should_use_a_specific_ranged_amount_of_values_to_retrieve_if_specified($client)
    {
        $attrResult = new Attribute('member;range=1501-1600');
        $entry = new Entry('dc=foo', $attrResult);

        $client->readOrFail('dc=foo', Argument::that(function ($attr) {
            return $attr[0]->getOptions()->first()->getLowRange() == '1501' && $attr[0]->getOptions()->first()->getHighRange() == '1600';
        }))->shouldBeCalled()->willReturn($entry);

        $this->getMoreValues('dc=foo', new Attribute('member;range=0-1500'), 100)->shouldBeEqualTo($attrResult);
    }
    
    function it_should_retrieve_all_values_for_a_specific_attribute($client)
    {
        $entry1 = new Entry('dc=foo', new Attribute('member;range=0-1500', 'foo'));
        $entry2 = new Entry('dc=foo', new Attribute('member;range=1501-*', 'bar'));

        $client->readOrFail('dc=foo', Argument::that(function ($attr) {
            return $attr[0]->getOptions()->first()->getLowRange() == '0' && $attr[0]->getOptions()->first()->getHighRange() == '*';
        }))->shouldBeCalled()->willReturn($entry1);
        $client->readOrFail('dc=foo', Argument::that(function ($attr) {
            return $attr[0]->getOptions()->first()->getLowRange() == '1501' && $attr[0]->getOptions()->first()->getHighRange() == '*';
        }))->shouldBeCalled()->willReturn($entry2);

        $this->getAllValues('dc=foo', 'member')->getValues()->shouldBeEqualTo(['foo', 'bar']);        
    }
}
