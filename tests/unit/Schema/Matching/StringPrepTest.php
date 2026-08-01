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
