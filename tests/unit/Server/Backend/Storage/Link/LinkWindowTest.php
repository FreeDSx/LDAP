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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Link;

use FreeDSx\Ldap\Entry\Option;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkWindow;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class LinkWindowTest extends TestCase
{
    public function test_an_option_that_is_not_a_range_asks_for_no_slice(): void
    {
        self::assertNull(LinkWindow::fromOption(new Option('lang-en')));
    }

    public function test_a_bounded_range_asks_for_the_values_it_names(): void
    {
        $window = LinkWindow::fromOption(new Option('range=1500-2999'));

        self::assertNotNull($window);
        self::assertSame(1500, $window->first);
        self::assertSame(2999, $window->last);
        self::assertSame(1500, $window->size(5000));
    }

    public function test_a_range_to_the_end_is_bounded_by_the_cap(): void
    {
        $window = LinkWindow::fromOption(new Option('range=1500-*'));

        self::assertNotNull($window);
        self::assertSame(1500, $window->first);
        self::assertNull($window->last);
        self::assertSame(1499, $window->size(1499));
    }

    /**
     * An option is case insensitive, and the draft defining this one spells it "Range=".
     */
    #[DataProvider('rangeSpellingProvider')]
    public function test_a_range_is_read_however_it_is_spelled(string $option): void
    {
        $window = LinkWindow::fromOption(new Option($option));

        self::assertNotNull($window);
        self::assertSame(0, $window->first);
        self::assertSame(500, $window->last);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function rangeSpellingProvider(): iterable
    {
        yield 'lowercase' => ['range=0-500'];
        yield 'as the draft spells it' => ['Range=0-500'];
        yield 'uppercase' => ['RANGE=0-500'];
    }

    public function test_a_range_naming_no_low_end_asks_from_the_first_value(): void
    {
        $window = LinkWindow::fromOption(new Option('range=-500'));

        self::assertNotNull($window);
        self::assertSame(0, $window->first);
        self::assertSame(500, $window->last);
    }

    public function test_a_range_naming_one_position_asks_for_one_value(): void
    {
        $window = LinkWindow::fromOption(new Option('range=1-1'));

        self::assertNotNull($window);
        self::assertSame(1, $window->first);
        self::assertSame(1, $window->last);
        self::assertSame(1, $window->size(1500));
        self::assertSame(
            'member;range=1-1',
            $window->nameFor('member', 1, more: true),
        );
    }

    public function test_the_cap_holds_a_slice_wider_than_it(): void
    {
        $window = LinkWindow::fromOption(new Option('range=0-9999'));

        self::assertSame(1500, $window?->size(1500));
    }

    /**
     * Nothing validates the option on the way in, so a slice that cannot be served has to be refused here.
     */
    #[DataProvider('malformedRangeProvider')]
    public function test_a_range_that_cannot_be_served_is_refused(string $option): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        LinkWindow::fromOption(new Option($option));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedRangeProvider(): iterable
    {
        yield 'no high end' => ['range=5-'];
        yield 'high end is not a number' => ['range=0-abc'];
        yield 'ends before it starts' => ['range=9-2'];
        yield 'no bounds at all' => ['range='];
    }

    public function test_the_whole_attribute_keeps_its_plain_name(): void
    {
        self::assertSame(
            'member',
            LinkWindow::whole()->nameFor('member', 12, more: false),
        );
    }

    public function test_a_truncated_attribute_is_named_with_what_it_holds(): void
    {
        self::assertSame(
            'member;range=0-1499',
            LinkWindow::whole()->nameFor('member', 1500, more: true),
        );
    }

    public function test_a_later_slice_is_named_from_where_it_starts(): void
    {
        $window = LinkWindow::fromOption(new Option('range=1500-*'));

        self::assertSame(
            'member;range=1500-2999',
            $window?->nameFor('member', 1500, more: true),
        );
    }

    public function test_the_last_slice_is_named_to_the_end(): void
    {
        $window = LinkWindow::fromOption(new Option('range=1500-*'));

        self::assertSame(
            'member;range=1500-*',
            $window?->nameFor('member', 200, more: false),
        );
    }
}
