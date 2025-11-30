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

namespace Tests\Unit\FreeDSx\Ldap\Entry;

use FreeDSx\Ldap\Entry\Option;
use FreeDSx\Ldap\Entry\Options;
use PHPUnit\Framework\TestCase;

class OptionsSpec extends TestCase
{
    private Options $subject;

    protected function setUp(): void
    {
        $this->subject = new Options(
            'foo',
            'Bar',
            'lang-en',
            'range=1500-*',
        );
    }
    
    public function test_it_should_get_the_first_option(): void
    {
        self::assertEquals(
            new Option('foo'),
            $this->subject->first(),
        );
    }
    
    public function test_it_should_get_the_last_option(): void
    {
        self::assertEquals(
            new Option('range=1500-*'),
            $this->subject->last(),
        );
    }
    
    public function test_it_should_return_null_for_the_first_option_when_there_are_none(): void
    {
        $this->subject = new Options();
        
        self::assertNull($this->subject->first());
    }
    
    public function test_it_should_return_null_for_the_last_option_when_there_are_none(): void
    {
        $this->subject = new Options();

        self::assertNull($this->subject->last());
    }
    
    public function test_it_should_get_a_semi_colon_separated_string_representation_calling_toString(): void
    {
        self::assertSame(
            'foo;Bar;lang-en;range=1500-*',
            $this->subject->toString(),
        );
    }
    
    public function test_it_should_sort_and_lowercase_the_string_representation_if_requested(): void
    {
        self::assertSame(
            'bar;foo;lang-en;range=1500-*',
            $this->subject->toString(true),
        );
    }

    public function test_it_should_have_a_string_representation(): void
    {
        self::assertSame(
            'foo;Bar;lang-en;range=1500-*',
            (string) $this->subject,
        );
    }
    
    public function test_it_should_get_the_count(): void
    {
        self::assertCount(
            4,
            $this->subject,
        );
    }

    public function test_it_should_get_an_array_of_options_if_requested(): void
    {
        self::assertEquals(
            [
                new Option('foo'),
                new Option('Bar'),
                new Option('lang-en'),
                new Option('range=1500-*')
            ],
            $this->subject->toArray(),
        );
    }
    
    public function test_it_should_add_an_option(): void
    {
        $this->subject->add('x-bar');

        self::assertTrue($this->subject->has('x-bar'));;
    }
    
    public function test_it_should_remove_an_option(): void
    {
        $this->subject->remove('foo');

        self::assertFalse($this->subject->has('foo'));
    }
    
    public function test_it_should_set_the_options(): void
    {
        $this->subject->set('foo');

        self::assertCount(
            1,
            $this->subject,
        );
    }
    
    public function test_it_should_check_for_an_option(): void
    {
        self::assertTrue($this->subject->has('foo'));
        self::assertFalse($this->subject->has('x-foo'));
    }
}
