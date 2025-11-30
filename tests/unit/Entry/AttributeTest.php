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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Option;
use FreeDSx\Ldap\Entry\Options;
use PHPUnit\Framework\TestCase;

class AttributeTest extends TestCase
{
    private Attribute $subject;

    protected function setUp(): void
    {
        $this->subject = new Attribute(
            'cn',
            'foo',
            'bar',
        );
    }

    public function test_it_should_get_the_name(): void
    {
        self::assertSame('cn', $this->subject->getName());

        $this->subject->getOptions()->add('foo');

        self::assertSame(
            'cn',
            $this->subject->getName()
        );
    }

    public function test_it_should_get_the_complete_attribute_description(): void
    {
        self::assertSame(
            'cn',
            $this->subject->getDescription()
        );

        $this->subject->getOptions()->add('foo');

        self::assertSame(
            'cn;foo',
            $this->subject->getDescription()
        );
    }

    public function test_it_should_return_false_for_hasOptions_when_there_are_none(): void
    {
        self::assertFalse($this->subject->hasOptions());
    }

    public function test_it_should_get_options(): void
    {
        self::assertEquals(
            new Options(),
            $this->subject->getOptions(),
        );
    }
    
    public function test_it_should_get_the_values(): void
    {
        self::assertSame(
            ['foo', 'bar'],
            $this->subject->getValues(),
        );
    }

    public function test_it_should_get_the_first_value_if_it_exists(): void
    {
        self::assertSame(
            'foo',
            $this->subject->firstValue(),
        );
    }

    public function test_it_should_get_the_last_value_if_it_exists(): void
    {
        self::assertSame(
            'bar',
            $this->subject->lastValue(),
        );
    }

    public function test_it_should_get_null_if_the_first_value_does_not_exist(): void
    {
        $this->subject = new Attribute('foo');

        self::assertNull($this->subject->firstValue());;
    }

    public function test_it_should_get_null_if_the_last_value_does_not_exist(): void
    {
        $this->subject = new Attribute('foo');

        self::assertNull($this->subject->lastValue());
    }

    public function test_it_should_have_a_string_representation(): void
    {
        self::assertSame(
            'foo, bar',
            (string) $this->subject,
        );
    }

    public function test_it_should_get_a_count_of_values(): void
    {
        self::assertCount(
            2,
            $this->subject,
        );
    }

    public function test_it_should_add_values(): void
    {
        $this->subject->add('foobar', 'meh');

        self::assertSame(
            ['foo', 'bar', 'foobar', 'meh'],
            $this->subject->getValues(),
        );
    }

    public function test_it_should_remove_values(): void
    {
        $this->subject->remove('bar');

        self::assertSame(
            ['foo'],
            $this->subject->getValues(),
        );
    }

    public function test_it_should_set_values(): void
    {
        $this->subject->set('foo');

        self::assertSame(
            ['foo'],
            $this->subject->getValues(),
        );
    }

    public function test_it_should_reset_values(): void
    {
        $this->subject->reset();

        self::assertEmpty($this->subject->getValues());
    }

    public function test_it_should_check_if_a_value_exists(): void
    {
        self::assertTrue($this->subject->has('foo'));
        self::assertFalse($this->subject->has('bleh'));
    }

    public function test_it_should_check_if_it_equals_another_attribute(): void
    {
        self::assertTrue($this->subject->equals(new Attribute('cn')));
        self::assertTrue($this->subject->equals(new Attribute('CN')));
        self::assertFalse($this->subject->equals(new Attribute('foo')));
    }

    public function test_it_should_check_if_it_equals_another_attribute_with_options(): void
    {
        self::assertFalse($this->subject->equals(new Attribute('cn;foo')));

        $this->subject->getOptions()->add('foo');

        self::assertTrue($this->subject->equals(new Attribute('cn;foo')));
    }
    
    public function test_it_should_be_check_equality_with_the_name_only_by_default(): void
    {
        $this->subject->getOptions()->add('foo');

        self::assertTrue($this->subject->equals(new Attribute('cn')));
    }

    public function test_it_should_be_check_equality_with_name_and_options_when_strict_is_set(): void
    {
        $this->subject->getOptions()->add('foo');

        self::assertFalse($this->subject->equals(new Attribute('cn'), true));;
    }
    
    public function test_it_should_escape_a_value(): void
    {
        self::assertSame(
            '\28foo=\2a\5cbar\29\00',
            Attribute::escape("(foo=*\bar)\x00")
        );
    }

    public function test_it_should_escape_a_value_to_complete_hex(): void
    {
        self::assertSame(
            '\66\6f\6f\62\61\72',
            Attribute::escapeAll("foobar"),
        );
    }

    public function test_it_should_ignore_an_empty_value_when_escaping(): void
    {
        self::assertSame(
            '',
            Attribute::escape(''),
        );
    }

    public function test_it_should_not_escape_a_string_that_is_already_hex_encoded(): void
    {
        self::assertSame(
            '\66\6f\6f\62\61\72',
            Attribute::escape('\66\6f\6f\62\61\72'),
        );
    }

    public function test_it_should_parse_options_in_the_attribute(): void
    {
        $this->subject = new Attribute(
            'foo;lang-en-us',
            'bar',
        );

        self::assertSame(
            'foo',
            $this->subject->getName(),
        );
        self::assertEquals(
            new Options(new Option('lang-en-us')),
            $this->subject->getOptions(),
        );
    }
}
