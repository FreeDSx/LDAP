<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Entry;

use FreeDSx\Ldap\Entry\Option;
use FreeDSx\Ldap\Entry\Options;
use PhpSpec\ObjectBehavior;

class OptionsSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo', 'Bar', 'lang-en', 'range=1500-*');    
    }
    
    function it_is_initializable()
    {
        $this->shouldHaveType(Options::class);
    }
    
    function it_should_be_countable()
    {
        $this->shouldImplement(\Countable::class);
    }
    
    function it_should_be_iterable()
    {
        $this->shouldImplement(\IteratorAggregate::class);
    }
    
    function it_should_get_the_first_option()
    {
        $this->first()->shouldBeLike(new Option('foo'));    
    }
    
    function it_should_get_the_last_option()
    {
        $this->last()->shouldBeLike(new Option('range=1500-*'));
    }
    
    function it_should_return_null_for_the_first_option_when_there_are_none()
    {
        $this->beConstructedWith(...[]);
        
        $this->first()->shouldBeNull();
    }
    
    function it_should_return_null_for_the_last_option_when_there_are_none()
    {
        $this->beConstructedWith(...[]);

        $this->last()->shouldBeNull();   
    }
    
    function it_should_get_a_semi_colon_separated_string_representation_calling_toString()
    {
        $this->toString()->shouldBeEqualTo('foo;Bar;lang-en;range=1500-*');
    }
    
    function it_should_sort_and_lowercase_the_string_representation_if_requested()
    {
        $this->toString(true)->shouldBeEqualTo('bar;foo;lang-en;range=1500-*');
    }
    
    function it_should_have_a_string_representation()
    {
        $this->__toString()->shouldBeEqualTo('foo;Bar;lang-en;range=1500-*');
    }
    
    function it_should_get_the_count()
    {
        $this->count()->shouldBeEqualTo(4);
    }

    function it_should_get_an_array_of_options_if_requested()
    {
        $this->toArray()->shouldBeLike([
            new Option('foo'), 
            new Option('Bar'),
            new Option('lang-en'),
            new Option('range=1500-*')
        ]);
    }
    
    function it_should_add_an_option()
    {
        $this->add('x-bar');
        $this->has('x-bar')->shouldBeEqualTo(true);
    }
    
    function it_should_remove_an_option()
    {
        $this->remove('foo');
        $this->has('foo')->shouldBeEqualTo(false);        
    }
    
    function it_should_set_the_options()
    {
        $this->set('foo');
        $this->count()->shouldBeEqualTo(1);
    }
    
    function it_should_check_for_an_option()
    {
        $this->has('bar')->shouldBeEqualTo(true);
        $this->has('x-foo')->shouldBeEqualTo(false);
    }
}
