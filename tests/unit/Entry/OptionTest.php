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
use PHPUnit\Framework\TestCase;

class OptionTest extends TestCase
{
    private Option $subject;

    protected function setUp(): void
    {
        $this->subject = new Option('foo');
    }

    public function test_it_should_detect_if_it_is_not_a_language_option(): void
    {
        self::assertFalse($this->subject->isLanguageTag());
    }
    
    public function test_it_should_detect_if_it_is_a_language_option(): void
    {
        $this->subject = new Option('lang-en');

        self::assertTrue($this->subject->isLanguageTag());
    }

    public function test_it_should_detect_if_it_is_not_a_range_option(): void
    {
        self::assertFalse($this->subject->isRange());
    }

    public function test_it_should_detect_if_it_is_a_range_option(): void
    {
        $this->subject = new Option('range=0-1500');

        self::assertTrue($this->subject->isRange());
    }
    
    public function test_it_should_get_the_high_range_value_of_an_option(): void
    {
        $this->subject = new Option('range=0-1500');

        self::assertSame(
            '1500',
            $this->subject->getHighRange(),
        );
    }
    
    public function test_it_should_return_an_empty_string_if_the_high_range_cannot_be_parsed(): void
    {
        self::assertSame(
            '',
            $this->subject->getHighRange(),
        );
    }
    
    public function test_it_should_get_the_low_range_value_of_an_option(): void
    {
        $this->subject = new Option('range=0-1500');

        self::assertSame(
            '0',
            $this->subject->getLowRange(),
        );
    }

    public function test_it_should_return_null_if_the_low_range_cannot_be_parsed(): void
    {
        self::assertNull($this->subject->getLowRange());
    }
    
    public function test_it_should_have_a_factory_method_for_a_range(): void
    {
        $this->subject = Option::fromRange('0');

        self::assertTrue($this->subject->isRange());
        self::assertSame(
            '0',
            $this->subject->getLowRange(),
        );
        self::assertSame(
            '*',
            $this->subject->getHighRange(),
        );
    }
    
    public function test_it_should_return_whether_the_option_starts_with_a_string(): void
    {
        self::assertTrue($this->subject->startsWith('fo'));
        self::assertFalse($this->subject->startsWith('bar'));
    }
    
    public function test_it_should_get_the_string_option_with_toString(): void
    {
        self::assertSame(
            'foo',
            $this->subject->toString(),
        );
    }
    
    public function test_it_should_have_a_string_representation(): void
    {
        self::assertSame(
            'foo',
            (string) $this->subject,
        );
    }
    
    public function test_it_should_check_for_equality_with_another_option(): void
    {
        self::assertTrue($this->subject->equals(new Option('FOO')));
        self::assertTrue($this->subject->equals(new Option('foo')));
        self::assertFalse($this->subject->equals(new Option('bar')));
    }
}
