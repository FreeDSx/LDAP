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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SqlFilterUtilityTest extends TestCase
{
    #[DataProvider('integerInsideProvider')]
    public function test_an_integer_is_inside_a_bound_only_when_its_magnitude_is_below_it(
        string $value,
        bool $isInside,
    ): void {
        self::assertSame(
            $isInside,
            SqlFilterUtility::isIntegerInside(
                $value,
                '9223372036854775807',
            ),
        );
    }

    /**
     * @return Generator<string, array{string, bool}>
     */
    public static function integerInsideProvider(): Generator
    {
        yield 'zero' => [
            '0',
            true,
        ];
        yield 'one below the bound' => [
            '9223372036854775806',
            true,
        ];
        yield 'one above the negated bound' => [
            '-9223372036854775806',
            true,
        ];
        yield 'the bound' => [
            '9223372036854775807',
            false,
        ];
        yield 'the negated bound' => [
            '-9223372036854775807',
            false,
        ];
        yield 'more digits than the bound' => [
            '10000000000000000000',
            false,
        ];
        yield 'leading zeros before a value inside' => [
            '000123',
            true,
        ];
        yield 'not an integer' => [
            '12a',
            false,
        ];
        yield 'a trailing newline' => [
            "5\n",
            false,
        ];
        yield 'empty' => [
            '',
            false,
        ];
    }

    public function test_escapes_percent(): void
    {
        self::assertSame(
            '50!%',
            SqlFilterUtility::escape('50%'),
        );
    }

    public function test_escapes_underscore(): void
    {
        self::assertSame(
            'a!_b',
            SqlFilterUtility::escape('a_b'),
        );
    }

    public function test_escapes_exclamation(): void
    {
        self::assertSame(
            'a!!b',
            SqlFilterUtility::escape('a!b'),
        );
    }

    public function test_escapes_multiple_special_chars(): void
    {
        self::assertSame(
            'a!%!_!!b',
            SqlFilterUtility::escape('a%_!b'),
        );
    }

    public function test_leaves_normal_chars_unchanged(): void
    {
        self::assertSame(
            'hello world',
            SqlFilterUtility::escape('hello world'),
        );
    }

    public function test_prefix_upper_bound_increments_the_last_byte(): void
    {
        self::assertSame(
            'seed-13',
            SqlFilterUtility::prefixUpperBound('seed-12'),
        );
    }

    public function test_prefix_upper_bound_increments_within_a_multibyte_character(): void
    {
        self::assertSame(
            'zoì',
            SqlFilterUtility::prefixUpperBound('zoë'),
        );
    }

    public function test_prefix_upper_bound_sorts_above_every_string_with_the_prefix(): void
    {
        $bound = SqlFilterUtility::prefixUpperBound('al');

        self::assertLessThan(
            0,
            strcmp(
                'al' . "\u{10FFFF}",
                $bound,
            ),
        );
        self::assertGreaterThan(
            0,
            strcmp(
                $bound,
                'alzzzz',
            ),
        );
    }

    public function test_prefix_upper_bound_refuses_an_empty_prefix(): void
    {
        $this->expectException(InvalidArgumentException::class);

        SqlFilterUtility::prefixUpperBound('');
    }

    public function test_prefix_upper_bound_refuses_a_non_utf8_prefix(): void
    {
        $this->expectException(InvalidArgumentException::class);

        SqlFilterUtility::prefixUpperBound("a\xFF");
    }

    public function test_up_to_eight_parts_are_joined_without_nesting(): void
    {
        self::assertSame(
            '(a) OR (b) OR (c) OR (d) OR (e) OR (f) OR (g) OR (h)',
            SqlFilterUtility::grouped(
                ['(a)', '(b)', '(c)', '(d)', '(e)', '(f)', '(g)', '(h)'],
                'OR',
            ),
        );
    }

    public function test_more_than_eight_parts_are_nested_in_groups_of_eight(): void
    {
        self::assertSame(
            '((a) AND (b) AND (c) AND (d) AND (e) AND (f) AND (g) AND (h)) AND ((i))',
            SqlFilterUtility::grouped(
                ['(a)', '(b)', '(c)', '(d)', '(e)', '(f)', '(g)', '(h)', '(i)'],
                'AND',
            ),
        );
    }

    public function test_the_nesting_grows_with_the_log_of_the_parts(): void
    {
        $sql = SqlFilterUtility::grouped(
            array_fill(
                0,
                4096,
                '(x)',
            ),
            'OR',
        );
        $depth = 0;
        $deepest = 0;

        foreach (str_split($sql) as $character) {
            $depth += match ($character) {
                '(' => 1,
                ')' => -1,
                default => 0,
            };
            $deepest = max(
                $deepest,
                $depth,
            );
        }

        self::assertSame(
            4,
            $deepest,
        );
        self::assertSame(
            4096,
            substr_count(
                $sql,
                '(x)',
            ),
        );
    }
}
