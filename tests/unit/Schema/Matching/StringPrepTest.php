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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Matching;

use FreeDSx\Ldap\Schema\Matching\StringPrep;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class StringPrepTest extends TestCase
{
    private StringPrep $subject;

    protected function setUp(): void
    {
        $this->subject = new StringPrep();
    }

    public function test_collapses_double_internal_spaces(): void
    {
        self::assertSame(
            'foo bar',
            $this->subject->prepareForEquality('foo  bar'),
        );
    }

    public function test_trims_leading_and_trailing_spaces(): void
    {
        self::assertSame(
            'foo',
            $this->subject->prepareForEquality('  foo  '),
        );
    }

    public function test_lowercases_ascii_when_folding(): void
    {
        self::assertSame(
            'foobar',
            $this->subject->prepareForEquality('FooBar'),
        );
    }

    public function test_does_not_lowercase_when_fold_disabled(): void
    {
        $subject = new StringPrep(foldCase: false);

        self::assertSame(
            'FooBar',
            $subject->prepareForEquality('FooBar'),
        );
    }

    public function test_strips_soft_hyphen(): void
    {
        self::assertSame(
            'foobar',
            $this->subject->prepareForEquality("foo\u{00AD}bar"),
        );
    }

    public function test_strips_zero_width_space(): void
    {
        self::assertSame(
            'foobar',
            $this->subject->prepareForEquality("foo\u{200B}bar"),
        );
    }

    /**
     * @param non-empty-string $value
     */
    #[DataProvider('mappedToNothingProvider')]
    public function test_the_map_step_removes_a_code_point_that_renders_as_nothing(string $value): void
    {
        self::assertSame(
            'admin',
            $this->subject->prepareForEquality($value),
        );
    }

    /**
     * RFC 4518 2.2 enumerates these; left in place, each makes a value that renders as "admin" into a second,
     * distinct value.
     *
     * @return iterable<string, array{non-empty-string}>
     */
    public static function mappedToNothingProvider(): iterable
    {
        yield 'left to right mark' => [
            "adm\u{200E}in",
        ];
        yield 'right to left mark' => [
            "adm\u{200F}in",
        ];
        yield 'left to right embedding' => [
            "adm\u{202A}in",
        ];
        yield 'pop directional formatting' => [
            "adm\u{202C}in",
        ];
        yield 'mongolian todo soft hyphen' => [
            "adm\u{1806}in",
        ];
        yield 'mongolian vowel separator' => [
            "adm\u{180E}in",
        ];
        yield 'object replacement character' => [
            "adm\u{FFFC}in",
        ];
        yield 'interlinear annotation anchor' => [
            "adm\u{FFF9}in",
        ];
        yield 'word joiner' => [
            "adm\u{2060}in",
        ];
        yield 'arabic end of ayah' => [
            "adm\u{06DD}in",
        ];
        yield 'syriac abbreviation mark' => [
            "adm\u{070F}in",
        ];
        yield 'control below the line breaks' => [
            "adm\x01in",
        ];
        yield 'control above the line breaks' => [
            "adm\x1Fin",
        ];
        yield 'delete' => [
            "adm\x7Fin",
        ];
        yield 'c1 control' => [
            "adm\u{009F}in",
        ];
        yield 'musical formatting' => [
            "adm\u{1D173}in",
        ];
        yield 'language tag' => [
            "adm\u{E0001}in",
        ];
        yield 'tag character' => [
            "adm\u{E0041}in",
        ];
    }

    /**
     * The line breaking controls are the exception: RFC 4518 2.2 maps them to SPACE rather than to nothing.
     */
    public function test_the_map_step_folds_a_line_break_to_a_space_rather_than_removing_it(): void
    {
        self::assertSame(
            'a b',
            $this->subject->prepareForEquality("a\nb"),
        );
    }

    public function test_folds_nbsp_to_space_then_collapses(): void
    {
        self::assertSame(
            'foo bar',
            $this->subject->prepareForEquality("foo\u{00A0}\u{00A0}bar"),
        );
    }

    public function test_fragment_collapses_interior_but_keeps_bounding_spaces(): void
    {
        self::assertSame(
            ' foo bar ',
            $this->subject->prepareFragment(' foo  bar '),
        );
    }

    public function test_normalizes_compatibility_form_when_available(): void
    {
        if (!class_exists(\Normalizer::class)) {
            self::markTestSkipped('NFKC requires ext-intl or symfony/polyfill-intl-normalizer.');
        }

        self::assertSame(
            'a',
            $this->subject->prepareForEquality("\u{FF21}"),
        );
    }

    public function test_folds_non_ascii_case_when_available(): void
    {
        if (!function_exists('mb_strtolower')) {
            self::markTestSkipped('Unicode case folding requires ext-mbstring or symfony/polyfill-mbstring.');
        }

        self::assertSame(
            'é',
            $this->subject->prepareForEquality('É'),
        );
    }
}
